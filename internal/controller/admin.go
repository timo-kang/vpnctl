// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"vpnctl/internal/api"
	"vpnctl/internal/metrics"
	"vpnctl/internal/pki"
)

// AcquireStateLock must be called before constructing or initializing the production
// server. It prevents two controllers loading independent writable registry copies.
func AcquireStateLock(dataDir string) (*os.File, error) {
	dir := filepath.Join(dataDir, "run")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0o700 || !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("%s must be a real directory owned by the controller user with mode 0700", dir)
	}
	fd, err := syscall.Open(filepath.Join(dir, "controller.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "controller.lock")
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("controller already owns data_dir: %w", err)
	}
	return file, nil
}

type adminActorKey struct{}

// localActor authenticates the Unix peer using kernel credentials. Headers and
// client certificates cannot impersonate a local administrator.
func localActor(conn net.Conn) (string, bool) {
	local, ok := conn.(*net.UnixConn)
	if !ok {
		return "", false
	}
	raw, err := local.SyscallConn()
	if err != nil {
		return "", false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return "", false
	}
	if cred.Uid != 0 && cred.Uid != uint32(os.Geteuid()) {
		return "", false
	}
	return "uid:" + strconv.FormatUint(uint64(cred.Uid), 10) + "/pid:" + strconv.Itoa(int(cred.Pid)), true
}

// startAdmin requires ownership established by AcquireStateLock. A leftover
// socket from a crashed owner is safe to unlink while holding that lock.
func (s *Server) startAdmin() (func(), error) {
	service, err := s.startAdminService()
	if err != nil {
		return nil, err
	}
	return service.stop, nil
}

func (s *Server) startAdminService() (*managedHTTP, error) {
	path := api.AdminSocketPath(s.cfg.DataDir)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", s.handleAdmin)
	server := &http.Server{
		Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if actor, ok := localActor(conn); ok {
				return context.WithValue(ctx, adminActorKey{}, actor)
			}
			return ctx
		},
	}
	return startHTTP(server, listener, false), nil
}

func tokenAuditID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("sha256:%x", sum[:12])
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	actor, ok := r.Context().Value(adminActorKey{}).(string)
	if !ok || actor == "" {
		slog.Warn("admin operation", "actor", "unauthenticated", "target", "admin", "result", "denied")
		writeJSONError(w, http.StatusForbidden, "local administrator credentials required")
		return
	}
	operation, target, result := "invalid", "admin", "rejected"
	defer func() {
		slog.Info("admin operation", "actor", actor, "operation", operation, "target", target, "result", result)
	}()
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req api.AdminRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, 400, "invalid admin request")
		return
	}
	var response api.AdminResponse
	var err error
	switch req.Operation {
	case "node.remove":
		operation = req.Operation
		if _, validationErr := pki.NodeIdentityURI(req.NodeID); validationErr != nil {
			writeJSONError(w, 400, validationErr.Error())
			return
		}
		target = req.NodeID
		err = s.removeNode(req.NodeID)
		if errors.Is(err, errNodeNotFound) {
			writeJSONError(w, 404, err.Error())
			return
		}
	case "pki.status", "pki.revoke", "ca.prepare", "ca.activate", "ca.retire", "ca.rollback", "pki.backup":
		operation, target = req.Operation, "pki"
		if req.Operation == "pki.revoke" {
			target = req.Fingerprint
		}
		response, err = s.adminPKI(req)
		if errors.Is(err, pki.ErrTransitionBlocked) {
			result = "rejected"
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
	case "token.create", "token.list", "token.revoke":
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
		operation, target = req.Operation, "tokens"
		if s.tokenStore == nil {
			writeJSONError(w, 409, "PKI is not enabled")
			return
		}
		switch req.Operation {
		case "token.create":
			ttl := 24 * time.Hour
			if req.TTL != "" {
				ttl, err = time.ParseDuration(req.TTL)
			}
			if err != nil || ttl < 0 {
				writeJSONError(w, 400, "TTL must be a nonnegative duration")
				return
			}
			response.Token, err = s.tokenStore.CreateWithOptions(ttl, req.SingleUse)
			if err == nil {
				target = tokenAuditID(response.Token)
			}
		case "token.list":
			response.Tokens, err = s.tokenStore.Records()
		case "token.revoke":
			if req.Token == "" {
				writeJSONError(w, 400, "token required")
				return
			}
			target = tokenAuditID(req.Token)
			err = s.tokenStore.Revoke(req.Token)
		}
	default:
		writeJSONError(w, 400, "unknown admin operation")
		return
	}
	if err != nil {
		result = "failed"
		slog.Error("admin mutation failed", "operation", operation, "err", err)
		writeJSONError(w, 500, "admin operation failed; inspect controller logs")
		return
	}
	result = "success"
	writeJSON(w, 200, response)
}

var errNodeNotFound = errors.New("node not found")

func (s *Server) removeNode(nodeID string) error {
	// Wait for already admitted authenticated requests, then exclude new ones until
	// the tombstone, dataplane and all volatile node state have been committed.
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, removed := s.reg.RemovedNodes[nodeID]; removed {
		return nil
	}
	next := cloneRegistry(s.reg)
	found := false
	for i, node := range next.Nodes {
		if node.ID == nodeID {
			next.Nodes = append(next.Nodes[:i], next.Nodes[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return errNodeNotFound
	}
	next.RemovedNodes[nodeID] = time.Now().UTC()
	if err := s.commitRegistryLocked(next, s.cfg.WGApply); err != nil {
		return err
	}
	delete(s.directOK, nodeID)
	for id, peers := range s.directOK {
		delete(peers, nodeID)
		if len(peers) == 0 {
			delete(s.directOK, id)
		}
	}
	metricsRemoveNode(nodeID)
	s.updateMetricsLocked()
	return nil
}

func metricsRemoveNode(nodeID string) {
	// Historical CSV samples remain immutable; only current labelled series vanish.
	metrics.DirectProbesTotal.DeletePartialMatch(prometheus.Labels{"node": nodeID})
	metrics.DirectProbesTotal.DeletePartialMatch(prometheus.Labels{"peer": nodeID})
}

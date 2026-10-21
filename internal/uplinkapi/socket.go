// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const socketName = "uplink.sock"
const lockName = "uplink.lock"

// Open every component without following symlinks. All ancestors must be owned
// by root or the expected service UID and unwritable by others. A root-owned
// sticky ancestor (e.g. /tmp in tests) cannot replace the private child directory.
// The final directory must be provisioned separately, owned by the service UID.
func runtimeDir(path string, uid uint32) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, st, errors.New("absolute canonical runtime directory required")
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, st, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, st, e
		}
		fd = next
		err = unix.Fstat(fd, &st)
		leaf := i == len(parts)-1
		stickyRoot := !leaf && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if err != nil || st.Uid != uid && st.Uid != 0 || st.Mode&0022 != 0 && !stickyRoot || leaf && (st.Uid != uid || st.Mode&07777 != 0700 && st.Mode&07777 != 0750) {
			unix.Close(fd)
			return -1, st, errors.New("unsafe runtime directory ownership or permissions")
		}
	}
	return fd, st, nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var readErr error
	err = raw.Control(func(fd uintptr) { cred, readErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || readErr != nil || cred == nil {
		return 0, errors.New("Unix peer credentials unavailable")
	}
	return cred.Uid, nil
}

type ownedListener struct {
	*net.UnixListener
	dir, lock int
	inode     unix.Stat_t
	once      sync.Once
}

func (l *ownedListener) Close() error {
	l.once.Do(func() {
		l.UnixListener.Close()
		var st unix.Stat_t
		if unix.Fstatat(l.dir, socketName, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Dev == l.inode.Dev && st.Ino == l.inode.Ino && st.Mode&unix.S_IFMT == unix.S_IFSOCK {
			_ = unix.Unlinkat(l.dir, socketName, 0)
		}
		unix.Close(l.lock)
		unix.Close(l.dir)
	})
	return nil
}

func listen(path string) (*ownedListener, error) {
	uid := uint32(os.Geteuid())
	dir, st, err := runtimeDir(path, uid)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			unix.Close(dir)
		}
	}()
	lock, err := unix.Openat(dir, lockName, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !keep {
			unix.Close(lock)
		}
	}()
	var ls unix.Stat_t
	if unix.Fstat(lock, &ls) != nil || ls.Mode&unix.S_IFMT != unix.S_IFREG || ls.Mode&0777 != 0600 || ls.Uid != uid || ls.Nlink != 1 {
		return nil, errors.New("unsafe uplink lock")
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("uplink runtime directory already owned")
	}
	var old unix.Stat_t
	err = unix.Fstatat(dir, socketName, &old, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if old.Mode&unix.S_IFMT != unix.S_IFSOCK || old.Uid != uid || old.Gid != st.Gid || old.Mode&0777 != 0660 {
			return nil, errors.New("refusing to replace unowned uplink socket")
		}
		if err = unix.Unlinkat(dir, socketName, 0); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	// Bind relative to the pinned directory; never check a path then resolve it
	// again through mutable ancestors. No service-wide umask/chown/mount changes.
	name := fmt.Sprintf("/proc/self/fd/%d/%s", dir, socketName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	l := &ownedListener{UnixListener: listener, dir: dir, lock: lock}
	if err = unix.Fstatat(dir, socketName, &l.inode, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		listener.Close()
		return nil, err
	}
	keep = true
	if err = unix.Fchownat(dir, socketName, -1, int(st.Gid), unix.AT_SYMLINK_NOFOLLOW); err == nil {
		err = unix.Fchmodat(dir, socketName, 0660, 0)
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Dial authenticates the endpoint independently of HTTP headers. Consumers
// must also validate the snapshot clock domain/deadline before using evidence.
func Dial(ctx context.Context, path string, serverUID uint32) (*net.UnixConn, error) {
	dir, ds, err := runtimeDir(path, serverUID)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if unix.Fstatat(dir, socketName, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != serverUID || st.Gid != ds.Gid || st.Mode&0777 != 0660 {
		return nil, errors.New("untrusted uplink socket")
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", fmt.Sprintf("/proc/self/fd/%d/%s", dir, socketName))
	if err != nil {
		return nil, err
	}
	c := conn.(*net.UnixConn)
	uid, err := peerUID(c)
	if err != nil || uid != serverUID {
		c.Close()
		return nil, errors.New("untrusted uplink server UID")
	}
	return c, nil
}

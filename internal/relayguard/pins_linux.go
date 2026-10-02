// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relayguard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Provisioned by deployment, never mounted by the relay process. Operations
// stay relative to a retained FD after rejecting symlinks/untrusted ancestors.
func pinDirectory() (*os.File, error) {
	path := os.Getenv("VPNCTL_BPF_ROOT")
	if path == "" {
		path = "/run/vpnctl-bpf"
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrConflict
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(path[1:], "/") {
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return nil, err
		}
		if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			unix.Close(fd)
			return nil, ErrConflict
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("open provisioned relay bpffs: %w", err)
		}
		fd = next
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err = unix.Fstat(fd, &st); err == nil {
		err = unix.Fstatfs(fd, &fs)
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 || fs.Type != unix.BPF_FS_MAGIC {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: require owned mode 0700 bpffs", ErrConflict)
	}
	return os.NewFile(uintptr(fd), path), nil
}
func pinName(o Owner, kind string) string { return "lease_" + o.Alias[7:] + "_" + kind }
func pinPath(dir *os.File, o Owner, kind string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), pinName(o, kind))
}
func pinExists(dir *os.File, o Owner, kind string) (bool, error) {
	var st unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), pinName(o, kind), &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return false, ErrConflict
	}
	return true, nil
}
func Preflight(o Owner) error {
	if !o.valid() {
		return ErrConflict
	}
	dir, err := pinDirectory()
	if err != nil {
		return err
	}
	defer dir.Close()
	for _, kind := range []string{"map", "program"} {
		exists, err := pinExists(dir, o, kind)
		if err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
	}
	return nil
}
func loadPins(o Owner, partial bool) (*ebpf.Map, *ebpf.Program, error) {
	if !o.valid() {
		return nil, nil, ErrConflict
	}
	dir, err := pinDirectory()
	if partial && errors.Is(err, unix.ENOENT) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()
	mapExists, err := pinExists(dir, o, "map")
	if err != nil {
		return nil, nil, err
	}
	progExists, err := pinExists(dir, o, "program")
	if err != nil {
		return nil, nil, err
	}
	if !mapExists {
		if partial && !progExists {
			return nil, nil, nil
		}
		return nil, nil, ErrConflict
	}
	m, err := ebpf.LoadPinnedMap(pinPath(dir, o, "map"), nil)
	if err != nil {
		return nil, nil, err
	}
	if !progExists {
		if partial {
			return m, nil, nil
		}
		m.Close()
		return nil, nil, ErrConflict
	}
	p, err := ebpf.LoadPinnedProgram(pinPath(dir, o, "program"), nil)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, p, nil
}

// RemovePins follows link removal. The caller retains its durable owner journal
// until both pins are gone, so an interrupted cleanup can be safely repeated.
func RemovePins(ctx context.Context, o Owner) error {
	h, err := handle(ctx)
	if err != nil {
		return err
	}
	defer h.Close()
	var missing netlink.LinkNotFoundError
	if _, err := h.LinkByIndex(o.Index); !errors.As(err, &missing) {
		return ErrConflict
	}
	if _, err := h.LinkByName(o.Interface); !errors.As(err, &missing) {
		return ErrConflict
	}

	if err := InspectPartial(ctx, o); err != nil {
		return err
	}
	dir, err := pinDirectory()
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	for _, kind := range []string{"program", "map"} {
		if err := unix.Unlinkat(int(dir.Fd()), pinName(o, kind), 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return nil
}

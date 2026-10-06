// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"syscall"
	"time"
)

const admissionSlots = 32
const admissionPoll = 25 * time.Millisecond

var ErrAdmissionFull = errors.New("node admission queue is full")

// admission is a FIFO turn among cooperating processes using the same cache.
// It grants no kernel/cache authority: the existing locks are still required.
// Live flock descriptors, not PIDs, timestamps or durable counters, identify
// waiters. SIGKILL/exec/Close releases the slot without stale queue cleanup.
// All files use the cache's private-file validation; fixed slots bound disk use.
type admission struct {
	*files
	slot   *os.File
	ticket uint64
}

func (a *admission) Close() error {
	var err error
	if a.slot != nil {
		err = a.slot.Close()
		a.slot = nil
	}
	if a.root != nil {
		err = errors.Join(err, a.root.Close())
		a.root = nil
	}
	return err
}

func admissionPause(ctx context.Context) error {
	timer := time.NewTimer(admissionPoll)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// scan allocates a ticket or checks its position while holding a short queue
// metadata lock. Never hold this lock while waiting or doing application work.
func (a *admission) scan(ctx context.Context) (first bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	guard, err := a.openFile("admission.lock", os.O_CREATE|os.O_RDWR)
	if err != nil {
		return false, err
	}
	defer guard.Close()
	if err = syscall.Flock(int(guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return false, nil
		}
		return false, err
	}
	var spare *os.File
	defer func() {
		if spare != nil {
			spare.Close()
		}
	}()
	minTicket, maxTicket := uint64(math.MaxUint64), uint64(0)
	seen := map[uint64]bool{}
	for i := 0; i < admissionSlots; i++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		f, err := a.openFile(fmt.Sprintf("admission-%02d", i), os.O_CREATE|os.O_RDWR)
		if err != nil {
			return false, err
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if a.slot == nil && spare == nil {
				spare = f
			} else {
				f.Close()
			}
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return false, err
		}
		// A live slot was fully published under this same metadata lock.
		var buf [9]byte
		n, readErr := f.ReadAt(buf[:], 0)
		f.Close()
		if n != 8 || readErr != io.EOF {
			return false, ErrCorrupt
		}
		ticket := binary.BigEndian.Uint64(buf[:8])
		if ticket == 0 || seen[ticket] {
			return false, ErrCorrupt
		}
		seen[ticket] = true
		minTicket, maxTicket = min(minTicket, ticket), max(maxTicket, ticket)
	}
	if a.slot == nil {
		if spare == nil {
			return false, ErrAdmissionFull
		}
		if maxTicket == math.MaxUint64 {
			return false, ErrCorrupt
		}
		a.ticket = maxTicket + 1
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], a.ticket)
		if err := spare.Truncate(0); err != nil {
			return false, err
		}
		if n, err := spare.WriteAt(buf[:], 0); err != nil || n != len(buf) {
			return false, errors.Join(err, io.ErrShortWrite)
		}
		// Deliberately no fsync: data has meaning only while this descriptor is
		// locked. A restart has no surviving tickets to replay or trust.
		a.slot, spare = spare, nil
		return maxTicket == 0, ctx.Err()
	}
	if !seen[a.ticket] {
		return false, ErrCorrupt
	}
	return a.ticket == minTicket, ctx.Err()
}

func waitAdmission(ctx context.Context, dir string) (*admission, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := openDirectory(dir, false)
	if err != nil {
		return nil, err
	}
	a := &admission{files: &files{root: root}}
	for {
		first, err := a.scan(ctx)
		if err == nil && first {
			return a, nil
		}
		if err == nil {
			err = admissionPause(ctx)
		}
		if err != nil {
			a.Close()
			return nil, err
		}
	}
}

// OpenQueued waits its turn in an existing node cache. The caller must bound
// ctx; waiting reads no approval and performs no lease renewal. The turn lasts
// until Store.Close, including the caller's namespace ownership. Nonparticipating
// cache users still exclude this caller through the original cache.lock.
func OpenQueued(ctx context.Context, dir string, opts Options) (*Store, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, errors.New("bounded node admission context required")
	}
	a, err := waitAdmission(ctx, dir)
	if err != nil {
		return nil, err
	}
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		var s *Store
		s, err = Open(dir, opts)
		if err == nil {
			queuedRoot, queueErr := a.root.Stat(".")
			openedRoot, rootErr := s.root.Stat(".")
			if queueErr != nil || rootErr != nil || !os.SameFile(queuedRoot, openedRoot) {
				err = ErrUnsafe
			} else {
				err = ctx.Err()
			}
			if err == nil {
				s.admission = a
				return s, nil
			}
			s.Close()
			break
		}
		if !errors.Is(err, ErrBusy) {
			break
		}
		if err = admissionPause(ctx); err != nil {
			break
		}
	}
	a.Close()
	return nil, err
}

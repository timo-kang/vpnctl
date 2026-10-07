// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package relaycache

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
)

func admissionOpenEvents(t *testing.T, dir string) func() map[string]int {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	return func() map[string]int {
		events := map[string]int{}
		var buf [16384]byte
		for {
			n, err := unix.Read(fd, buf[:])
			if errors.Is(err, unix.EAGAIN) {
				return events
			}
			if err != nil {
				t.Fatal(err)
			}
			for offset := 0; offset < n; {
				if n-offset < 16 {
					t.Fatal("incomplete inotify event")
				}
				length := int(binary.NativeEndian.Uint32(buf[offset+12 : offset+16]))
				if length > n-offset-16 {
					t.Fatal("incomplete inotify name")
				}
				name := strings.TrimRight(string(buf[offset+16:offset+16+length]), "\x00")
				if strings.HasPrefix(name, "admission-") || name == "admission.lock" {
					events[name]++
				}
				offset += 16 + length
			}
		}
	}
}

// Observe real filesystem opens, not elapsed time or an implementation counter.
// A known live predecessor must not make every waiting poll reopen all 32 slots.
func TestAdmissionWaitingPollHasBoundedWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := privateTempDir(t)
		holder := newAdmission(t, dir)
		scanAdmission(t, holder, true)
		opens := admissionOpenEvents(t, dir)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		finished := make(chan error, 1)
		go func() {
			a, err := waitAdmission(ctx, dir)
			if a != nil {
				a.Close()
			}
			finished <- err
		}()
		synctest.Wait()
		opens() // Initial allocation must retain the full scan.
		for range 3 {
			time.Sleep(admissionPoll)
			synctest.Wait()
			got := opens()
			if got["admission-00"] == 0 || len(got) > 2 {
				t.Fatalf("blocked poll reopened queue instead of checking predecessor: %v", got)
			}
		}
		cancel()
		synctest.Wait()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Fatal("waiting cancellation", err)
		}
		holder.Close()
		next := newAdmission(t, dir)
		scanAdmission(t, next, true)
	})
}

func pollAdmission(t *testing.T, a *admission, want bool) {
	t.Helper()
	first, err := a.poll(context.Background())
	if err != nil || first != want {
		t.Fatalf("poll first=%t want=%t err=%v", first, want, err)
	}
}

func writeAdmissionTicket(t *testing.T, f *os.File, ticket uint64) {
	t.Helper()
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], ticket)
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if n, err := f.WriteAt(data[:], 0); err != nil || n != len(data) {
		t.Fatal("write ticket", n, err)
	}
}

func TestAdmissionHintChangesRequireFullScan(t *testing.T) {
	for _, kind := range []string{"released", "moved", "replaced_same_ticket", "symlink", "mode", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTempDir(t)
			holder, waiter := newAdmission(t, dir), newAdmission(t, dir)
			scanAdmission(t, holder, true)
			scanAdmission(t, waiter, false)
			pollAdmission(t, waiter, false)
			path := filepath.Join(dir, "admission-00")
			wantFirst, wantErr := false, error(nil)
			switch kind {
			case "released":
				holder.Close()
				wantFirst = true
			case "moved":
				if err := os.Rename(path, filepath.Join(dir, "admission-03")); err != nil {
					t.Fatal(err)
				}
			case "replaced_same_ticket", "symlink":
				if err := os.Rename(path, filepath.Join(dir, "saved-holder")); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					if err := os.Symlink("saved-holder", path); err != nil {
						t.Fatal(err)
					}
					wantErr = ErrUnsafe
				} else {
					replacement, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
					if err != nil {
						t.Fatal(err)
					}
					defer replacement.Close()
					if err := syscall.Flock(int(replacement.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
						t.Fatal(err)
					}
					writeAdmissionTicket(t, replacement, holder.ticket)
				}
			case "mode":
				if err := holder.slot.Chmod(0644); err != nil {
					t.Fatal(err)
				}
				wantErr = ErrUnsafe
			case "corrupt":
				if err := holder.slot.Truncate(1); err != nil {
					t.Fatal(err)
				}
				wantErr = ErrCorrupt
			}
			opens := admissionOpenEvents(t, dir)
			first, err := waiter.poll(context.Background())
			if first != wantFirst || !errors.Is(err, wantErr) {
				t.Fatalf("first=%t want=%t err=%v want=%v", first, wantFirst, err, wantErr)
			}
			got := opens()
			if got["admission.lock"] == 0 || wantErr == nil && got["admission-31"] == 0 {
				t.Fatal("changed predecessor bypassed full queue validation", got)
			}
		})
	}
}

// A free slot can be reused at the same inode with a different ticket. It must
// not continue blocking its former successor, even while the new owner is live.
func TestAdmissionHintSlotReuseAndRejoinFIFO(t *testing.T) {
	dir := privateTempDir(t)
	holder, older, younger := newAdmission(t, dir), newAdmission(t, dir), newAdmission(t, dir)
	scanAdmission(t, holder, true)
	scanAdmission(t, older, false)
	scanAdmission(t, younger, false)
	pollAdmission(t, older, false)
	pollAdmission(t, younger, false)
	oldInfo, err := holder.slot.Stat()
	if err != nil {
		t.Fatal(err)
	}
	holder.Close()
	rejoined := newAdmission(t, dir)
	scanAdmission(t, rejoined, false)
	newInfo, err := rejoined.slot.Stat()
	if err != nil || !os.SameFile(oldInfo, newInfo) || rejoined.ticket <= younger.ticket {
		t.Fatal("same-inode ticket reuse not exercised", err)
	}
	pollAdmission(t, younger, false)
	pollAdmission(t, rejoined, false)
	pollAdmission(t, older, true)
	older.Close()
	pollAdmission(t, rejoined, false)
	pollAdmission(t, younger, true)
	younger.Close()
	pollAdmission(t, rejoined, true)
}

// While a publisher holds admission.lock, polling must not inspect its
// partially rewritten predecessor slot or misclassify it as corruption.
func TestAdmissionHintPartialPublicationWaitsForMetadataLock(t *testing.T) {
	dir := privateTempDir(t)
	holder, waiter := newAdmission(t, dir), newAdmission(t, dir)
	scanAdmission(t, holder, true)
	scanAdmission(t, waiter, false)
	holder.Close()
	guard, err := waiter.openFile("admission.lock", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := syscall.Flock(int(guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	publisher, err := waiter.openFile("admission-00", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if err := syscall.Flock(int(publisher.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Truncate(1); err != nil {
		t.Fatal(err)
	}
	pollAdmission(t, waiter, false) // No false corruption or admission while publishing.
	writeAdmissionTicket(t, publisher, waiter.ticket+1)
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	pollAdmission(t, waiter, true)
}

func TestAdmissionHintCannotGrantAroundCorruptQueue(t *testing.T) {
	for _, corrupt := range []string{"own", "younger"} {
		t.Run(corrupt, func(t *testing.T) {
			dir := privateTempDir(t)
			holder, waiter, younger := newAdmission(t, dir), newAdmission(t, dir), newAdmission(t, dir)
			scanAdmission(t, holder, true)
			scanAdmission(t, waiter, false)
			scanAdmission(t, younger, false)
			broken := waiter
			if corrupt == "younger" {
				broken = younger
			}
			writeAdmissionTicket(t, broken.slot, 0)
			pollAdmission(t, waiter, false) // A hint only establishes that work remains blocked.
			holder.Close()
			if first, err := waiter.poll(context.Background()); first || !errors.Is(err, ErrCorrupt) {
				t.Fatal("hint bypassed corruption before admission", first, err)
			}
		})
	}
}

func TestAdmissionHintCancellationDoesNotOpenFiles(t *testing.T) {
	dir := privateTempDir(t)
	holder, waiter := newAdmission(t, dir), newAdmission(t, dir)
	scanAdmission(t, holder, true)
	scanAdmission(t, waiter, false)
	opens := admissionOpenEvents(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if first, err := waiter.poll(ctx); first || !errors.Is(err, context.Canceled) {
		t.Fatal(first, err)
	}
	if got := opens(); len(got) != 0 {
		t.Fatal("cancelled waiter performed filesystem work", got)
	}
	holder.Close()
	pollAdmission(t, waiter, true)
}

// Slot flock probes can themselves briefly acquire a released slot. Serialize
// them with publishers/scanners so that descriptor cannot masquerade as a live
// queue member to another allocator.
func TestAdmissionHintDoesNotInspectSlotDuringPublication(t *testing.T) {
	dir := privateTempDir(t)
	holder, waiter := newAdmission(t, dir), newAdmission(t, dir)
	scanAdmission(t, holder, true)
	scanAdmission(t, waiter, false)
	guard, err := waiter.openFile("admission.lock", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := syscall.Flock(int(guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	opens := admissionOpenEvents(t, dir)
	pollAdmission(t, waiter, false)
	if got := opens(); got["admission-00"] != 0 {
		t.Fatal("hint inspected a slot outside the queue metadata lock", got)
	}
}

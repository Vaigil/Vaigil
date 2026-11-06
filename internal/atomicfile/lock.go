// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"errors"
	"fmt"
	"os"
)

// Lock takes an exclusive lock on path for a read-decide-write sequence
// across processes, and returns what releases it.
//
// The lock belongs to an open descriptor (flock, or LockFileEx on Windows),
// so the kernel releases it when the holder closes it or dies. There is no
// lock file to go stale, no age after which another process may take it
// over, and so no moment at which two processes both hold it: the race the
// create-exclusive lock file it replaces had, where two processes found it
// stale together and one deleted the other's live lock.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the lock %s: %w", path, err)
	}
	if err := lockExclusive(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot take the lock %s: %w", path, err)
	}
	return func() {
		unlockFile(f)
		f.Close()
	}, nil
}

// ErrHeld is TryLock's answer when another holder has the lock now.
var ErrHeld = errors.New("the lock is held")

// TryLock is Lock without waiting: it takes the lock if nobody holds it, and
// returns ErrHeld at once if somebody does. For work where a second runner
// should be told one is already going rather than queue behind it — a
// detection run, an estate sync. The lock is the same kernel lock as Lock's,
// so a holder that died has released it.
func TryLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open the lock %s: %w", path, err)
	}
	held, err := tryLockExclusive(f)
	if err != nil || held {
		f.Close()
		if held {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("cannot take the lock %s: %w", path, err)
	}
	return func() {
		unlockFile(f)
		f.Close()
	}, nil
}

// Held reports whether somebody holds the lock at path now, by trying it.
func Held(path string) bool {
	unlock, err := TryLock(path)
	if err != nil {
		return errors.Is(err, ErrHeld)
	}
	unlock()
	return false
}

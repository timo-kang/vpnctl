//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Only the controller's PATH changes, inside the disposable test container.
// Delay exactly one showconf before reading/applying, never the application path.
func slowReconcileEnvironment(t *testing.T, dir string) ([]string, func()) {
	t.Helper()
	realWG, err := exec.LookPath("wg")
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(dir, "slow-wg")
	if err := os.Mkdir(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "slow-reconcile")
	entered := marker + "-entered"
	wrapper := `#!/bin/sh
if [ "$1" = showconf ] && [ -f "$VPNCTL_SLOW_MARKER" ]; then
 rm "$VPNCTL_SLOW_MARKER"
 : > "$VPNCTL_SLOW_ENTERED"
 sleep 2
fi
exec "$VPNCTL_REAL_WG" "$@"
`
	if err := os.WriteFile(filepath.Join(binDir, "wg"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + binDir + ":" + os.Getenv("PATH"), "VPNCTL_REAL_WG=" + realWG, "VPNCTL_SLOW_MARKER=" + marker, "VPNCTL_SLOW_ENTERED=" + entered}
	inject := func() {
		t.Helper()
		if err := os.WriteFile(marker, []byte("once"), 0600); err != nil {
			t.Fatal(err)
		}
		eventually(t, 5*time.Second, "slow controller reconciliation entered", func() error { _, err := os.Stat(entered); return err })
		time.Sleep(3 * time.Second)
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal(fmt.Errorf("slow command fault not consumed: %v", err))
		}
	}
	return env, inject
}

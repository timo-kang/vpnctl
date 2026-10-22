"""One additive, pre-activation metadata hook shared by both product modes."""
import hashlib
import json
from pathlib import Path
from packet_trace import replace_once, write

REPO = Path(__file__).resolve().parents[2]
ANCHOR = '\tf := build(t, paths, groupFD, results, initial)\n'
HOOK = '\tprivateStorageProvenance(t, f, report)\n'


def helper_text():
    source = (REPO / 'scripts/ci/storage_probe.py').read_text()
    return '''//go:build integration
package integration
import (
 "context"
 "encoding/json"
 "os/exec"
 "path/filepath"
 "testing"
 "time"
 "vpnctl/internal/config"
)
func privateStorageProvenance(t *testing.T, f *m3AuthorityFixture, report map[string]any) {
 requireIsolatedGuest(t)
 missing := func(reason string) { report["private_storage_provenance"] = map[string]any{"available":false,"reason":reason} }
 cfg, err := config.Load(f.node)
 if err != nil || cfg.Node == nil { missing("config_unavailable"); return }
 cache := cfg.Node.RelayCacheDir
 if cache == "" { cache = filepath.Join(cfg.Node.PKIDir,"relay-cache") }
 ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
 defer cancel()
 raw, err := exec.CommandContext(ctx,"ip","netns","exec",f.robot,"python3","-c",''' + json.dumps(source) + ''',cache).Output()
 if err != nil || len(raw)>1<<20 { missing("probe_unavailable"); return }
 if !json.Valid(raw) { missing("invalid_probe"); return }
 report["private_storage_provenance"] = json.RawMessage(raw)
}
'''


def prepare(source, root):
    relative = 'tests/integration/m3_observation_capacity_test.go'
    replacement = root / 'storage-capacity.go'
    replacement.write_text(replace_once((source / relative).read_text(), ANCHOR, ANCHOR + HOOK))
    helper = root / 'storage-provenance_test.go'
    helper.write_text(helper_text())
    overlay = root / 'storage-overlay.json'
    write(overlay, {'Replace': {str(source / relative): str(replacement),
          str(source / 'tests/integration/private_storage_provenance_test.go'): str(helper)}})
    return overlay, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (replacement, helper)}

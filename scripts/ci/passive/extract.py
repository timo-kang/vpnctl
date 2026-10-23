"""Export only the named evidence, repairing a private COPY if needed."""
import json
from pathlib import Path
import re
import subprocess
from outer_guard import outer_guard, digest
from analyze import analyze, check_recording
from export_contract import validate_mode, validate_raw

def main():
    outer_guard()
    disks = list(Path('/work').glob('vm-*/guest.qcow2'))
    verdicts = list(Path('/results').glob('application-capacity-*/verdict.json'))
    if len(disks) != 1 or len(verdicts) != 1:
        raise RuntimeError('exactly one retained VM disk and verdict required')
    status = json.loads(verdicts[0].read_text())['application-capacity-8']
    rows = status.get('reports', [])
    if len(rows) > 3 or any(not re.fullmatch(r'm3-authority-\d+', r['fixture']) for r in rows):
        raise RuntimeError('unexpected private fixture identities')
    mode = Path(__file__).with_name('mode').read_text().strip()
    if mode not in ('0', '1'): raise RuntimeError('explicit trace mode required')
    raw, recovered = Path('/work/extract.raw'), Path('/work/extract-recovered.raw')
    if raw.exists() or recovered.exists(): raise RuntimeError('fresh export files required')
    subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw', str(disks[0]), str(raw)], check=True)
    before = digest(raw)
    subprocess.run(['cp', '--sparse=always', str(raw), str(recovered)], check=True)
    if digest(recovered) != before: raise RuntimeError('disk copy differs')
    check = subprocess.run(['e2fsck', '-p', str(recovered)], capture_output=True, text=True, timeout=120)
    audit = {'original_sha256_before': before, 'original_sha256_after': digest(raw),
             'recovered_sha256': digest(recovered), 'e2fsck_exit': check.returncode,
             'e2fsck_stdout': check.stdout, 'e2fsck_stderr': check.stderr}
    Path('/results/extraction-audit.json').write_text(json.dumps(audit, indent=2))
    if check.returncode not in (0,1) or audit['original_sha256_after'] != before:
        raise RuntimeError('export recovery failed or original changed')
    out = Path('/results/private-guest/results'); out.mkdir(parents=True, mode=0o700, exist_ok=False)
    checks = []
    for row in rows:
        fixture = out/row['fixture']; fixture.mkdir(mode=0o700)
        item = {'fixture': row['fixture'], 'trace': mode == '1', 'files': {}, 'errors': []}
        for name in ('application-mixed-candidates.json', 'private-passive.json', 'private-passive.ready', 'private-passive.log'):
            try:
                dest = fixture/name
                p = subprocess.run(['debugfs', '-R', f'dump /var/lib/vpnctl-vm/results/{row["fixture"]}/{name} {dest}', str(recovered)],
                                   check=True, capture_output=True, text=True)
                if dest.is_file(): item['files'][name] = {'sha256': digest(dest), 'bytes': dest.stat().st_size}
                elif 'File not found by ext2_lookup' not in p.stderr:
                    raise RuntimeError('could not establish file absence: '+name)
            except Exception as error: item['errors'].append(str(error))
        try:
            if json.loads((fixture/'application-mixed-candidates.json').read_text()) != row['report']:
                raise RuntimeError('durable report differs from original observer response')
            artifacts = set(item['files'])-{'application-mixed-candidates.json'}
            validate_mode(row['report'], mode, artifacts)
            if mode == '1':
                if (fixture/'private-passive.ready').read_text() != 'ready\n':
                    raise RuntimeError('collector readiness differs')
                recording = json.loads((fixture/'private-passive.json').read_text())
                validate_raw(recording, row['report']['private_trace_summary'])
                check_recording(recording)
        except Exception as error: item['errors'].append(str(error))
        checks.append(item)
        Path('/results/export.json').write_text(json.dumps({'trace': mode == '1', 'fixtures': checks}, indent=2))
    complete = len(rows) == 3 and all(not item['errors'] for item in checks)
    if mode == '1':
        # Raw counters alone cannot establish coverage of the actual payloads.
        # Keep missing/pre-SYN attribution explicit, never infer packet loss.
        attribution = analyze(Path('/results'))
        Path('/results/attribution.json').write_text(json.dumps(attribution, indent=2))
        complete = complete and attribution['integration_coverage_complete']
    print(json.dumps({'reports': len(rows), 'trace': mode == '1', 'evidence_complete': complete}))
    raise SystemExit(0 if complete else 1)


if __name__ == "__main__": main()

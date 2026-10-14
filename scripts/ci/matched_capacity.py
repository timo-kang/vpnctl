#!/usr/bin/env python3
"""One preregistered comparison on one disposable GitHub-hosted runner."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import traceback

SOURCES = {'A': '73a5d5f1ad7ebf24d6d28503f24e43c39ad19d40',
           'B': 'd5d7877d1ebb783359b03c74e543866a04de3c46'}
HARNESS = ['observer.py', 'make_image.py', 'guest_agent.py', 'manager_dhcp.py',
           'nft_delay.py', 'fsync_fault.py', 'vpnctl-vm-agent.service']
BINARIES = {'vpnctl', 'integration.test', 'vpnctl-legacy', 'vpnctl-lease-v1', 'vpnctl-lease-v2'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.PIPE).strip()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def schedule():
    rows = []
    for pair in range(1, 5):
        for arm in ('AB' if pair % 2 else 'BA'):
            rows.append({'sequence': len(rows)+1, 'pair': pair, 'arm': arm,
                         'cases': [4, 8] if pair % 2 else [8, 4], 'source': SOURCES[arm]})
    return rows


def checked_source(path, source):
    return (read_command(['git', 'rev-parse', 'HEAD'], path) == source
            and not read_command(['git', 'status', '--porcelain'], path))


def execute_schedule(root, sources, image, invoke):
    """Never substitute, retry or skip a scheduled attempt after a test failure."""
    results = []
    boot = Path('/proc/sys/kernel/random/boot_id').read_text()
    for row in schedule():
        destination = root / f"run-{row['sequence']:02d}-pair{row['pair']}-{row['arm']}"
        destination.mkdir(mode=0o700)
        (destination / 'artifacts').mkdir(mode=0o700)
        record = dict(row, start_monotonic_ns=time.monotonic_ns(), host_load_before=os.getloadavg())
        write_json(destination / 'invocation.json', record)
        try:
            if not checked_source(sources[row['arm']], row['source']):
                raise RuntimeError('source_drift')
            if Path('/proc/sys/kernel/random/boot_id').read_text() != boot:
                raise RuntimeError('host_boot_changed')
            code = invoke(row, destination, sources[row['arm']], image)
            record['exit_code'] = code
        except Exception as error:
            # Arbitrary subprocess output may contain credentials. Keep only the
            # exception class; the underlying command log is in private evidence.
            record.update(exit_code=125, infrastructure_error=type(error).__name__)
            (destination / 'infrastructure-error.log').write_text(traceback.format_exc())
        record.update(finish_monotonic_ns=time.monotonic_ns(), host_load_after=os.getloadavg())
        write_json(destination / 'invocation.json', record)
        results.append(record)
        write_json(root / 'progress.json', results)
    write_json(root / 'complete.json', {'invocations': len(results), 'all_exit_zero': all(r['exit_code'] == 0 for r in results)})
    return 0 if all(r['exit_code'] == 0 for r in results) else 1


def work_directories():
    return {str(path): (path.stat().st_dev, path.stat().st_ino)
            for path in Path('/tmp').glob('vpnctl-vm.*') if path.is_dir() and not path.is_symlink()}


def retain_binaries(root, destination, before, after):
    """Prove new invocation work independently of the optional late manifest."""
    manifests = list((destination / 'artifacts').glob('run-*.txt'))
    created = {name: identity for name, identity in after.items() if name not in before}
    write_json(destination / 'work-ownership.json', {'before': before, 'created': created})
    if len(created) > 1:
        raise ValueError('ambiguous_work_ownership')
    if not created:
        if manifests:
            raise ValueError('manifest_work_not_proven')
        return  # Runner may fail before creating any private work directory.
    name, identity = next(iter(created.items()))
    work = Path(name)
    stat = work.lstat()
    if (not re.fullmatch(r'/tmp/vpnctl-vm\.[A-Za-z0-9_]{6,16}', name)
            or work.is_symlink() or work.resolve() != work
            or (stat.st_dev, stat.st_ino) != tuple(identity)
            or stat.st_uid != os.getuid() or stat.st_mode & 0o777 != 0o700):
        raise ValueError('private_work_owner_invalid')
    records = {}
    for binary in sorted(BINARIES):
        path = work / 'input' / binary
        if not path.exists():
            continue  # Pre-build failure: preserve whatever bytes exist.
        if not path.is_file() or path.is_symlink() or path.resolve() != path:
            raise ValueError('binary_path_invalid')
        actual = digest(path)
        target = root / 'binaries' / actual
        if not target.exists():
            shutil.copyfile(path, target)
        if digest(target) != actual:
            raise ValueError('retained_binary_mismatch')
        records[binary] = {'sha256': actual, 'original_path': str(path), 'retained_path': str(target.relative_to(root))}
    write_json(destination / 'retained-binaries.json', records)
    # Only this invocation's newly created inode, after all available executable
    # bytes and the original process/log evidence were independently retained.
    # Pre-manifest image failures must not fill disk and bias later attempts.
    shutil.rmtree(work)
    if len(manifests) == 1:
        expected = {}
        for line in manifests[0].read_text().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
            if match and Path(match[2]).name in BINARIES:
                expected[Path(match[2]).name] = (match[1], match[2])
        if set(records) != BINARIES or set(expected) != BINARIES or any(
                (r['sha256'], r['original_path']) != expected[n] for n, r in records.items()):
            raise ValueError('manifest_binary_mismatch')
    elif len(manifests) > 1:
        raise ValueError('ambiguous_manifest')


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('disposable GitHub-hosted runner required')
    repo = Path(__file__).resolve().parents[2]
    root = Path(os.environ['VPNCTL_MATCHED_ROOT']).resolve()
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    if (root / 'plan.json').exists():
        raise SystemExit('existing schedule must never be restarted')
    (root / 'binaries').mkdir(mode=0o700)
    sources = {}
    for arm, source in SOURCES.items():
        path = root / ('source-' + arm)
        read_command(['git', 'worktree', 'add', '--detach', str(path), source], repo)
        if not checked_source(path, source):
            raise RuntimeError('source_not_exact')
        sources[arm] = path
    read_command(['git', 'diff', '--exit-code', SOURCES['A'], SOURCES['B'], '--',
                  'scripts/test-vm.sh', 'tests/vm', 'tests/integration'], repo)
    plan = {'schema': 1, 'sources': SOURCES, 'schedule': schedule(),
            'experiment_commit': read_command(['git', 'rev-parse', 'HEAD'], repo),
            'experiment_clean': not read_command(['git', 'status', '--porcelain'], repo),
            'harness': {name: digest(sources['A'] / 'tests/vm' / name) for name in HARNESS},
            'plan_sha256': digest(repo / 'scripts/ci/PLAN.md'),
            'runner_sha256': digest(Path(__file__)),
            'github_run_id': os.environ['GITHUB_RUN_ID'], 'github_run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
            'go_version': read_command(['go', 'version']),
            'host_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    if not plan['experiment_clean'] or os.environ['GITHUB_RUN_ATTEMPT'] != '1':
        raise RuntimeError('dirty_or_rerun_experiment')
    write_json(root / 'plan.json', plan)
    shutil.copyfile(repo / 'scripts/ci/PLAN.md', root / 'PLAN.md')
    # Build exactly once from the common baseline harness, then pin its image ID
    # for all sixteen VM exercises. Package/network work ends before comparison.
    with (root / 'image-build.log').open('wb') as log:
        subprocess.run(['docker', 'build', '--cpu-period=100000', '--cpu-quota=100000', '--memory=2g',
                        '--iidfile', str(root / 'image-id'), '-f', 'tests/vm/Dockerfile', 'tests/vm'],
                       cwd=sources['A'], env=dict(os.environ, DOCKER_BUILDKIT='0'), stdout=log, stderr=subprocess.STDOUT, check=True)
    image = (root / 'image-id').read_text().strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('image_id_invalid')
    inside = ['/opt/vpnctl-vm/' + n if n in ('observer.py', 'make_image.py') else
              '/guest-root/etc/systemd/system/' + n if n.endswith('.service') else '/guest-root/opt/vpnctl-vm/' + n for n in HARNESS]
    output = read_command(['docker', 'run', '--rm', '--network', 'none', '--cpus=1', '--memory=128m',
                           '--memory-swap=128m', '--pids-limit=16', '--cap-drop', 'ALL', '--security-opt',
                           'no-new-privileges', '--read-only', '--entrypoint', 'sha256sum', image, *inside])
    embedded = {Path(line.split()[1]).name: line.split()[0] for line in output.splitlines()}
    if embedded != plan['harness']:
        raise RuntimeError('embedded_harness_mismatch')
    write_json(root / 'image-provenance.json', {'image_id': image, 'embedded_harness': embedded})

    def invoke(row, destination, source, pinned_image):
        env = dict(os.environ, GOMAXPROCS='2', VPNCTL_VM_CPUS='1', VPNCTL_VM_RACE='1',
                   VPNCTL_VM_IMAGE=pinned_image, VPNCTL_ARTIFACT_DIR=str(destination/'artifacts'), VPNCTL_KEEP_VM_WORK='1')
        for key in ('GOFLAGS', 'VPNCTL_TEST_BINARY', 'VPNCTL_VM_MANAGERS'):
            env.pop(key, None)
        os.umask(0o022)  # Cap-free image builder must be able to read /input.
        before = work_directories()
        with (destination / 'runner.log').open('xb') as log:
            result = subprocess.run(['bash', 'scripts/test-vm.sh', '--case',
                                     *[f'application-capacity-{n}' for n in row['cases']],
                                     '--robot-cpus', '0.5', '--cpu-layout', 'shared'],
                                    cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
        # Record the original test exit even if retention itself fails.
        write_json(destination / 'process-exit.json', {'exit_code': result.returncode})
        retain_binaries(root, destination, before, work_directories())
        return result.returncode
    return execute_schedule(root, sources, image, invoke)


if __name__ == '__main__':
    raise SystemExit(main())

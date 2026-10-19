#!/usr/bin/env python3
"""Experiment only: build once, vary only robot quota on one CI runner."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lab', REPO / 'scripts/lab/runner.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
SOURCE = '888b83b991c1857f9114c59a3deb3cb76cf8506a'
SUITE = '02b32013ceaf0ad36e22216335767b7dc5604965'
BUILDER = 'golang@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a'
CELLS = ((1, '0.5'), (2, '1'), (3, '1'), (4, '0.5'))
TOOLS = ('scripts/ci/identical_image.py', 'scripts/lab/runner.py', 'scripts/ci/IDENTICAL_IMAGE.md',
         '.github/workflows/reliability.yml', 'scripts/ci/seal_identical.py',
         'tests/vm/observer.py', 'tests/vm/guest_agent.py', 'tests/vm/Dockerfile',
         'tests/integration/m3_runtime_counters_test.go', 'tests/integration/m3_runtime_counters_unit_test.go',
         'tests/integration/m3_observation_capacity_test.go')
BINARIES = ('vpnctl', 'integration.test', *lab.LEGACY)
IMAGE_FILES = ('guest.qcow2', 'initrd', 'vmlinuz', 'image.json')
BUNDLE_FILES = (['runtime.tar', 'build.json'] + ['input/'+n for n in BINARIES]
                + ['image/'+n for n in IMAGE_FILES] + [n+'.build-info' for n in BINARIES])


def suite_revision():
    return SUITE


def controller_revision():
    return subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()


def check_suite_changes(names):
    allowed = {'.github/workflows/reliability.yml'}
    if any(n not in allowed and not n.startswith(('scripts/ci/', 'tests/vm/')) for n in names):
        raise ValueError('unexpected product or integration test change in quota cohort')


def clean_controller():
    previous = lab.SOURCE
    try:
        lab.SOURCE = REPO
        commit = lab.clean_source()
        changes = lab.output(['git', '-C', str(REPO), 'diff', '--name-only', SUITE, commit]).splitlines()
        check_suite_changes(changes)
        return commit
    finally:
        lab.SOURCE = previous


def require_disposable():
    if any(os.environ.get(k) != v for k, v in {
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_RUN_ATTEMPT': '1'
    }.items()):
        raise RuntimeError('build only on a fresh disposable GitHub runner; no workflow reruns')


def safe_file(root, name):
    path = root / name
    if not path.is_file() or path.resolve() != path.absolute() or path.stat().st_nlink != 1:
        raise ValueError('regular non-linked file required: '+name)
    return path


def inventory(bundle):
    expected = set(BUNDLE_FILES)
    entries = list(bundle.rglob('*'))
    if any(p.is_symlink() or not (p.is_dir() or p.is_file()) for p in entries):
        raise ValueError('nonregular bundle entry')
    actual = {p.relative_to(bundle).as_posix() for p in entries if p.is_file()}
    if actual != expected:
        raise ValueError('unexpected or missing bundle files')
    return {name: {'sha256':lab.digest(safe_file(bundle, name)), 'bytes':(bundle/name).stat().st_size}
            for name in sorted(expected)}


def verify(root):
    manifest = json.loads(safe_file(root, 'bundle-manifest.json').read_text())
    if manifest.get('controller_revision') != controller_revision():
        raise ValueError('controller revision differs')
    if manifest.get('suite_revision') != suite_revision():
        raise ValueError('suite revision differs')
    if manifest['source'] != SOURCE or manifest['cells'] != [list(c) for c in CELLS]:
        raise ValueError('source or schedule differs')
    if manifest['tools'] != {n:lab.digest(REPO/n) for n in TOOLS}:
        raise ValueError('controller/protocol bytes differ')
    if manifest['files'] != inventory(root/'bundle'):
        raise ValueError('transported bytes differ')
    build = json.loads((root/'bundle/build.json').read_text())
    if (build.get('suite_revision') != manifest['suite_revision']
            or build.get('controller_revision') != manifest['controller_revision']
            or build['source'] != SOURCE or build['race'] is not True):
        raise ValueError('wrong build cohort')
    image = json.loads((root/'bundle/image/image.json').read_text())
    if set(image['sha256']) != set(IMAGE_FILES)-{'image.json'} or set(image['binaries']) != set(BINARIES):
        raise ValueError('incomplete guest identity')
    for name, digest in image['sha256'].items():
        if digest != lab.digest(root/'bundle/image'/name):
            raise ValueError('guest image identity differs')
    for name, digest in image['binaries'].items():
        if digest != lab.digest(root/'bundle/input'/name):
            raise ValueError('executable identity differs')
    if lab.image_id(build['runner_image']) != build['runner_image']:
        raise ValueError('runtime identity differs')
    return build


def check_build(text, name):
    if ': go1.25.0' not in text.splitlines()[0]:
        raise ValueError('unexpected compiler')
    settings = {}
    for line in text.splitlines()[1:]:
        fields = line.strip().split('\t', 1)
        if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            if key in settings:
                raise ValueError('duplicate build setting')
            settings[key] = value
    if settings.get('GOOS') != 'linux' or settings.get('GOARCH') != 'amd64':
        raise ValueError('wrong target')
    if name in ('vpnctl', 'integration.test') and settings.get('-race') != 'true':
        raise ValueError('race instrumentation missing')
    if name == 'vpnctl' and (settings.get('vcs.revision') != SOURCE or settings.get('vcs.modified') != 'false'):
        raise ValueError('source identity missing or dirty')


def prepare(root, cpuset):
    require_disposable()
    controller_commit = clean_controller()
    if shutil.disk_usage(root).free < 24*1024**3:
        raise RuntimeError('24 GiB free required before preparation')
    source = root/'source'
    subprocess.run(['git', 'clone', '--no-hardlinks', str(REPO), str(source)], check=True)
    subprocess.run(['git', '-C', str(source), 'checkout', '--detach', SOURCE], check=True)
    lab.SOURCE = source
    if lab.clean_source() != SOURCE:
        raise ValueError('build source mismatch')
    suite = root/'suite'
    suite_commit = suite_revision()
    subprocess.run(['git', 'clone', '--no-hardlinks', str(REPO), str(suite)], check=True)
    subprocess.run(['git', '-C', str(suite), 'checkout', '--detach', suite_commit], check=True)
    # CLI is old product source; instrumented test suite is a separate clean revision.
    lab.SOURCE = suite
    if lab.clean_source() != suite_commit:
        raise ValueError('suite checkout mismatch')
    lab.SOURCE = source
    bundle = root/'bundle'; bundle.mkdir(mode=0o700)
    for name in ('input', 'image'):
        (bundle/name).mkdir(mode=0o755 if name == 'input' else 0o777)
    # umask is deliberately private; set child permissions explicitly for cap-free UID 0.
    (bundle/'image').chmod(0o777)
    (bundle/'input').chmod(0o755)
    for name in ('cache', 'tmp', 'legacy'):
        (root/name).mkdir(mode=0o700)
    env = dict(os.environ, DOCKER_BUILDKIT='0')
    with (root/'runtime-build.log').open('xb') as stream:
        subprocess.run(lab.DOCKER+['build', '--cpu-period=100000', '--cpu-quota=100000',
            '--cpuset-cpus='+cpuset, '--memory=2g', '--memory-swap=2g', '--iidfile', str(root/'runtime-id'),
            '-f', str(REPO/'tests/vm/Dockerfile'), str(REPO/'tests/vm')],
            env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=2400)
    runtime = lab.image_id((root/'runtime-id').read_text().strip())
    lab.require_success(lab.execute(lab.DOCKER+['pull', BUILDER], root/'builder-pull.log', timeout=1200))
    builder = lab.image_id(BUILDER)
    code = 'set -euo pipefail\n'
    code += 'go build -p=2 -race -o /lab/bundle/input/vpnctl ./cmd/vpnctl\n'
    code += "go -C /suite test -p=2 -race -tags=integration ./tests/integration -run '^TestRuntime(Counter|Role|Capture)' -count=1\n"
    code += 'go -C /suite test -p=2 -race -tags=integration -c -o /lab/bundle/input/integration.test ./tests/integration\n'
    for name, revision in lab.LEGACY.items():
        code += f'mkdir /lab/legacy/{name}\ngit archive {revision} | tar -x -C /lab/legacy/{name}\n'
        code += f'go -C /lab/legacy/{name} build -p=2 -o /lab/bundle/input/{name} ./cmd/vpnctl\n'
    for name in BINARIES:
        code += f'go version -m /lab/bundle/input/{name} > /lab/bundle/{name}.build-info\n'
    name = 'vpnctl-identical-build-'+lab.uuid.uuid4().hex[:12]
    args = lab.container(name, '2', '4g', cpuset, 'bridge') + [
        '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m', '--user', f'{os.getuid()}:{os.getgid()}',
        '--workdir', '/src', '--mount', f'type=bind,src={source},dst=/src,readonly',
        '--mount', f'type=bind,src={suite},dst=/suite,readonly',
        '--mount', f'type=bind,src={root},dst=/lab', '-e', 'GOMAXPROCS=2', '-e', 'GOTOOLCHAIN=local',
        '-e', 'GOENV=off', '-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'GIT_CONFIG_SYSTEM=/dev/null',
        '-e', 'GOCACHE=/lab/cache/build', '-e', 'GOMODCACHE=/lab/cache/mod', '-e', 'GOTMPDIR=/lab/tmp',
        '--entrypoint', 'bash', builder, '-c', code]
    lab.require_success(lab.execute(args, root/'compile.log', name, timeout=2400))
    for name in BINARIES:
        check_build((bundle/(name+'.build-info')).read_text(), name)
    name = 'vpnctl-identical-image-'+lab.uuid.uuid4().hex[:12]
    args = lab.container(name, '1', '2g', cpuset) + [
        '--mount', f'type=bind,src={bundle}/input,dst=/input,readonly',
        '--mount', f'type=bind,src={bundle}/image,dst=/out',
        '--entrypoint', 'python3', runtime, '/opt/vpnctl-vm/make_image.py']
    lab.require_success(lab.execute(args, root/'image.log', name))
    # Save the pristine runtime, not any container writable layer or guest overlay.
    subprocess.run(lab.DOCKER+['image', 'save', '--output', str(bundle/'runtime.tar'), runtime], check=True, timeout=600)
    if lab.clean_source() != SOURCE:
        raise ValueError('source changed during build')
    lab.SOURCE = suite
    if lab.clean_source() != suite_commit:
        raise ValueError('suite changed during build')
    lab.SOURCE = source
    if clean_controller() != controller_commit:
        raise ValueError('controller changed during build')
    lab.write(bundle/'build.json', {'source':SOURCE, 'suite_revision':suite_commit, 'controller_revision':controller_commit, 'race':True, 'runner_image':runtime, 'builder_image':builder})
    lab.write(root/'bundle-manifest.json', {'source':SOURCE, 'suite_revision':suite_commit, 'controller_revision':controller_commit, 'cells':CELLS,
        'tools':{n:lab.digest(REPO/n) for n in TOOLS}, 'files':inventory(bundle)})
    verify(root)


def runtime_args(root, run, build, cpuset, sequence, robot_cpu):
    name = 'vpnctl-identical-'+lab.uuid.uuid4().hex[:12]
    args = lab.runtime_command(root/'bundle', run, build['runner_image'], cpuset, name, ['application-capacity-8'])
    args[args.index('--cpus=1')] = '--cpus=2'
    return name, args + ['--robot-cpus', robot_cpu, '--cpu-layout', 'split', '--runtime-counters', '1']


def host_context():
    return {n:Path('/proc', n).read_text() for n in ('cpuinfo', 'loadavg', 'pressure/cpu', 'pressure/memory', 'pressure/io')}


def run(root, cpuset, site, invoke=None):
    build = verify(root)
    runs = root/('runs-'+site); runs.mkdir(mode=0o700)
    baseline = lab.host_snapshot(); lab.write(runs/'host-initial.json', baseline)
    records = []
    for sequence, robot_cpu in CELLS:
        verify(root)
        destination = runs/f'{sequence:02d}'; destination.mkdir(mode=0o700)
        for child in ('work', 'results'):
            (destination/child).mkdir(mode=0o700)
        before = lab.host_snapshot(); lab.verify_host(baseline, before)
        lab.write(destination/'host-before.json', before)
        lab.write(destination/'pressure-before.json', host_context())
        name, args = runtime_args(root, destination, build, cpuset, sequence, robot_cpu)
        record = {'sequence':sequence, 'layout':'split', 'robot_cpus':robot_cpu, 'runtime_counters':'1', 'command':args, 'started_monotonic_ns':time.monotonic_ns()}
        lab.write(destination/'invocation.json', record)
        try:
            record['exit_code'] = (invoke(sequence, destination) if invoke else
                lab.execute(args, destination/'run.log', name, timeout=1200))
        except Exception as error:
            record.update(exit_code=125, infrastructure_error=type(error).__name__)
        finally:
            after = lab.host_snapshot(); lab.write(destination/'host-after.json', after)
            lab.write(destination/'pressure-after.json', host_context())
        record['finished_monotonic_ns'] = time.monotonic_ns()
        lab.write(destination/'exit.json', record)
        lab.verify_host(baseline, after)
        records.append(record)
        print(json.dumps({k:record[k] for k in ('sequence', 'layout', 'robot_cpus', 'runtime_counters', 'exit_code')}), flush=True)
    verify(root)
    lab.write(runs/'complete.json', records)
    return 0 if all(r['exit_code'] == 0 for r in records) else 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'run'])
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--cpuset', required=True, type=lab.cpu_set)
    parser.add_argument('--site', choices=['ci'], default='ci')
    args = parser.parse_args(); root = args.root.absolute()
    if root != root.resolve() or root == REPO or REPO in root.parents:
        raise ValueError('private root outside checkout, without symlinks, required')
    lab.mount_path(root)
    if args.phase == 'prepare':
        before = lab.host_snapshot(); lab.write(root/'host-before-preparation.json', before)
        try:
            prepare(root, args.cpuset)
        finally:
            after = lab.host_snapshot(); lab.write(root/'host-after-preparation.json', after)
            lab.verify_host(before, after)
        return 0
    require_disposable()
    clean_controller()
    return run(root, args.cpuset, args.site)


if __name__ == '__main__':
    raise SystemExit(main())

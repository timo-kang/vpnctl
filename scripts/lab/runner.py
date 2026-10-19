#!/usr/bin/env python3
"""Prepare and qualify an isolated QEMU lab without installing host tooling.

Host requirements: Python >=3.9, Git, Docker with cgroup v2, and /dev/kvm.
Only the runtime container receives KVM's supplementary group. No host ACL,
package, service, clock, networking or power configuration is changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

SOURCE = Path(__file__).resolve().parents[2]
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
LEGACY = {'vpnctl-legacy':'6e2da45c89de2d3ad2e4c930f1037472e6440692',
          'vpnctl-lease-v1':'fb0ca2e9684af827ac2afc4dd0cb9afcb0ca3e8b',
          'vpnctl-lease-v2':'b4ba9e7793b123e4b47bd2fc5acfdf9b2698a26b'}


def output(args):
    return subprocess.check_output(args, text=True).strip()


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            result.update(chunk)
    return result.hexdigest()


def mount_path(path):
    if any(c in str(path) for c in (',', '\n', '\r')):
        raise ValueError('unsupported mount path')
    return str(path)


def cpu_set(value):
    if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*', value):
        raise ValueError('invalid CPU set')
    cpus = []
    for part in value.split(','):
        a, _, b = part.partition('-'); start, end = int(a), int(b or a)
        if not 0 <= start <= end < 8192:
            raise ValueError('invalid CPU range')
        cpus.extend(range(start, end+1))
    if len(cpus) < 2 or len(cpus) != len(set(cpus)) or not set(cpus) <= os.sched_getaffinity(0):
        raise ValueError('at least two distinct available CPUs required')
    return value


def clean_source():
    # Go 1.25 can misidentify the enclosing checkout for a linked worktree.
    if not (SOURCE / '.git').is_dir() or output(['git', '-C', str(SOURCE), 'status', '--porcelain']):
        raise RuntimeError('use an independent clean clone with a real .git directory')
    return output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'])


def host_snapshot():
    ids = output(DOCKER + ['ps', '--no-trunc', '-q']).splitlines()
    containers = {}
    for identity in ids:
        containers[identity] = output(DOCKER + ['inspect', '--format', '{{.State.StartedAt}}/{{.RestartCount}}/{{.State.Running}}', identity])
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'containers':containers}


def verify_host(before, after):
    if before['boot_id'] != after['boot_id']:
        raise RuntimeError('host boot changed; isolation unqualified')
    if any(after['containers'].get(key) != value for key, value in before['containers'].items()):
        raise RuntimeError('preexisting container changed; investigate external activity before qualification')


def container(name, cpus, memory, cpuset, network='none'):
    return DOCKER + ['run', '--rm', '--name', name, '--label', 'vpnctl.lab.owner='+name,
        '--network', network, '--cpus='+cpus, '--cpuset-cpus='+cpuset,
        '--memory='+memory, '--memory-swap='+memory, '--pids-limit=256',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges']


def cleanup(name):
    check = subprocess.run(DOCKER + ['inspect', '--format', '{{index .Config.Labels "vpnctl.lab.owner"}}', name], capture_output=True, text=True)
    if check.returncode == 0 and check.stdout.strip() == name:
        subprocess.run(DOCKER + ['rm', '-f', name], check=True, stdout=subprocess.DEVNULL)


def execute(args, log, name=None, timeout=1800):
    try:
        with log.open('xb') as stream:
            return subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout).returncode
    finally:
        if name:
            cleanup(name)


def require_success(code):
    if code != 0:
        raise RuntimeError('preparation failed; retain logs and do not reuse this directory')


def image_id(reference):
    identity = output(DOCKER + ['image', 'inspect', '--format', '{{.Id}}', reference])
    if not re.fullmatch('sha256:[0-9a-f]{64}', identity):
        raise ValueError('invalid image identity')
    return identity


def prepare(root, cpuset, builder, runner):
    commit = clean_source()
    if shutil.disk_usage(root).free < 24*1024**3:
        raise RuntimeError('at least 24 GiB free disk required')
    for name in ('input', 'image', 'cache', 'tmp', 'runs'):
        (root/name).mkdir(mode=0o700)
    # Capability-free UID 0 needs traversal/read access to binary input too.
    # The enclosing 0700 lab root still denies access to other host users.
    (root/'input').chmod(0o755)
    (root/'image').chmod(0o777)
    builder_id = image_id(builder)
    runner_id = image_id(runner)
    write(root/'inputs.json', {'source':commit, 'builder_image':builder_id, 'runner_image':runner_id, 'cpuset':cpuset, 'legacy':LEGACY})
    name = 'vpnctl-lab-read-'+uuid.uuid4().hex[:12]
    args = container(name, '1', '64m', cpuset) + ['--read-only',
        '--user', f'{os.getuid()}:{os.getgid()}', '--entrypoint', 'python3', runner_id,
        '-c', "import ast; from pathlib import Path; [ast.parse(Path('/opt/vpnctl-vm', n).read_text()) for n in ('observer.py', 'make_image.py')]"]
    require_success(execute(args, root/'runtime-readability.log', name, timeout=30))
    code = 'set -euo pipefail\n'
    code += 'go build -p=2 -o /lab/input/vpnctl ./cmd/vpnctl\n'
    code += 'go test -p=2 -tags=integration -c -o /lab/input/integration.test ./tests/integration\n'
    for name, revision in LEGACY.items():
        code += f'mkdir /lab/{name}\ngit archive {revision} | tar -x -C /lab/{name}\ngo -C /lab/{name} build -p=2 -o /lab/input/{name} ./cmd/vpnctl\n'
    code += 'go version -m /lab/input/vpnctl > /lab/build-info.txt\n'
    name = 'vpnctl-lab-build-'+uuid.uuid4().hex[:12]
    args = container(name, '2', '4g', cpuset, 'bridge') + ['--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
        '--user', f'{os.getuid()}:{os.getgid()}', '--workdir', '/src',
        '--mount', f'type=bind,src={mount_path(SOURCE)},dst=/src,readonly',
        '--mount', f'type=bind,src={mount_path(root)},dst=/lab',
        '-e', 'GOMAXPROCS=2', '-e', 'GOTOOLCHAIN=local', '-e', 'GOENV=off',
        '-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'GIT_CONFIG_SYSTEM=/dev/null',
        '-e', 'GOCACHE=/lab/cache/build', '-e', 'GOMODCACHE=/lab/cache/mod', '-e', 'GOTMPDIR=/lab/tmp',
        '--entrypoint', 'bash', builder_id, '-c', code]
    require_success(execute(args, root/'compile.log', name))
    info = (root/'build-info.txt').read_text()
    if 'vcs.revision='+commit not in info or 'vcs.modified=false' not in info:
        raise RuntimeError('compiled CLI source identity missing or dirty')
    name = 'vpnctl-lab-image-'+uuid.uuid4().hex[:12]
    args = container(name, '1', '2g', cpuset) + [
        '--mount', f'type=bind,src={root}/input,dst=/input,readonly',
        '--mount', f'type=bind,src={root}/image,dst=/out',
        '--entrypoint', 'python3', runner_id, '/opt/vpnctl-vm/make_image.py']
    require_success(execute(args, root/'image.log', name))
    hashes = {p.name:digest(p) for p in (root/'input').iterdir()}
    if hashes != json.loads((root/'image/image.json').read_text())['binaries']:
        raise RuntimeError('guest executable hashes differ')
    if clean_source() != commit:
        raise RuntimeError('source changed during preparation')
    return {'source':commit, 'builder_image':builder_id, 'runner_image':runner_id,
        'cpuset':cpuset, 'binaries':hashes, 'image_manifest_sha256':digest(root/'image/image.json')}


def runtime_command(root, run, image, cpuset, name, cases):
    return container(name, '1', '2g', cpuset) + ['--device', '/dev/kvm', '--read-only',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m', '--user', f'{os.getuid()}:{os.getgid()}',
        '--group-add', str(os.stat('/dev/kvm').st_gid),
        '--mount', f'type=bind,src={mount_path(root)}/image,dst=/input,readonly',
        '--mount', f'type=bind,src={mount_path(run)}/work,dst=/work',
        '--mount', f'type=bind,src={mount_path(run)}/results,dst=/results',
        image, '--case', *cases]


def run_cases(root, cases):
    prepared = json.loads((root/'prepared.json').read_text())
    if clean_source() != prepared['source'] or digest(root/'image/image.json') != prepared['image_manifest_sha256']:
        raise RuntimeError('prepared source or manifest changed')
    image = image_id(prepared['runner_image']); cpuset = cpu_set(prepared['cpuset'])
    identity = uuid.uuid4().hex[:12]; run = root/'runs'/identity; run.mkdir(mode=0o700)
    for name in ('work', 'results'):
        (run/name).mkdir(mode=0o700)
    before = host_snapshot(); write(run/'host-before.json', before)
    args = runtime_command(root, run, image, cpuset, 'vpnctl-lab-test-'+identity, cases)
    write(run/'invocation.json', {'source':prepared['source'], 'cases':cases, 'command':args})
    try:
        code = execute(args, run/'run.log', 'vpnctl-lab-test-'+identity, timeout=1200)
        write(run/'exit.json', {'exit_code':code})
    except BaseException as error:
        write(run/'exit.json', {'exit_code':None, 'infrastructure_error':type(error).__name__})
        raise
    finally:
        after = host_snapshot(); write(run/'host-after.json', after)
    verify_host(before, after)
    if clean_source() != prepared['source']:
        raise RuntimeError('source changed during run')
    print('Original VM exit:', code, 'private evidence:', run)
    return code


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--cpuset', type=cpu_set, required=True)
    p.add_argument('--builder-image', required=True)
    p.add_argument('--runner-image', required=True)
    p = sub.add_parser('run')
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--case', nargs='+', choices=['boot', 'reboot', 'reset', 'suspend'], required=True)
    args = parser.parse_args(); root = args.root.absolute()
    if root != root.resolve():
        raise ValueError('lab root must not traverse symlinks')
    mount_path(root)
    if args.command == 'prepare':
        if root == SOURCE or SOURCE in root.parents:
            raise ValueError('lab root must be outside the source checkout')
        clean_source()
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        before = host_snapshot(); write(root/'host-before.json', before)
        try:
            prepared = prepare(root, args.cpuset, args.builder_image, args.runner_image)
        finally:
            after = host_snapshot(); write(root/'host-after.json', after)
            verify_host(before, after)
        write(root/'prepared.json', prepared)
        print('Prepared private VM image:', root)
        return 0
    return run_cases(root, args.case)


if __name__ == '__main__':
    raise SystemExit(main())

"""Four fresh trace-ON VMs on one disposable CI runner; no retry or threshold change."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from kvm_access import prepare_kvm, kvm_snapshot
from passive_overlay import prepare, prepare_context

REPO = Path(__file__).resolve().parents[2]
SOURCE = '14ccf89cafd941b8d6fd2727bdbd69f8addc1c67'
CELLS = (1, 2, 3, 4)


def write(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')


def require_disposable():
    if any(os.environ.get(k) != v for k, v in {
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_RUN_ATTEMPT': '1',
    }.items()):
        raise RuntimeError('fresh disposable GitHub runner required; no reruns')


def schedule(invoke):
    # A failure remains in the outcome while later predeclared trials still run.
    return [invoke(index) for index in CELLS]


def cell_args():
    return ['./scripts/test-vm.sh', '--case', 'application-capacity-8',
            '--robot-cpus', '1', '--cpu-layout', 'split']


def check_build(info):
    lines = info.splitlines()
    if not lines or not lines[0].endswith(': go1.25.0'):
        raise ValueError('unexpected compiler')
    settings = {}
    for line in lines[1:]:
        fields = line.strip().split('\t', 1)
        if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            if key in settings:
                raise ValueError('duplicate build setting')
            settings[key] = value
    expected = {'-race': 'true', 'GOOS': 'linux', 'GOARCH': 'amd64',
                'vcs.revision': SOURCE, 'vcs.modified': 'false'}
    if any(settings.get(k) != v for k, v in expected.items()):
        raise ValueError('product identity/race setting differs')


def run(root):
    require_disposable()
    source = root / 'source'
    subprocess.run(['git', 'clone', '--no-hardlinks', '--no-checkout', str(REPO), str(source)],
                   check=True, preexec_fn=lambda: os.umask(0o022))
    subprocess.run(['git', '-C', str(source), 'checkout', '--detach', SOURCE],
                   check=True, preexec_fn=lambda: os.umask(0o022))
    if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']):
        raise ValueError('dirty source')
    env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='')
    binary = root / 'vpnctl'
    subprocess.run(['go', 'build', '-p=2', '-race', '-o', str(binary), './cmd/vpnctl'],
                   cwd=source, env=env, check=True, timeout=1200)
    binary.chmod(0o755)
    info = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
    check_build(info)
    write(root / 'product.json', {'revision': SOURCE, 'build_info': info,
          'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
    write(root / 'protocol.json', {'source': SOURCE, 'controller': subprocess.check_output(
        ['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
        'race': True, 'cells': list(CELLS), 'trace': True,
        'robot_cpus': 1, 'server_cpus': 1, 'outer_cpus': 2, 'qualification': False,
        'original_run': '39699878690', 'host_kernel': os.uname().release,
        'host_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'host_affinity': sorted(os.sched_getaffinity(0))})
    overlay, hashes = prepare(source, root)
    context = prepare_context(source, root)
    write(root / 'diagnostic-inputs.json', {'overlay': hashes, 'vm_context': {
        str(p.relative_to(context)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in context.rglob('*') if p.is_file()}})
    subprocess.run(['docker', 'build', '--cpu-period=100000', '--cpu-quota=100000', '--memory=2g',
        '--iidfile', str(root / 'image-id'), '-f', str(context / 'Dockerfile'), str(context)],
        env=dict(env, DOCKER_BUILDKIT='0'), check=True, timeout=2400)
    image = (root / 'image-id').read_text().strip()
    (root / 'runs').mkdir()

    def invoke(index):
        cell = root / 'runs' / f'{index:02}'
        cell.mkdir()
        prepare_kvm(cell)
        args = cell_args()
        write(cell / 'invocation.json', {'index': index, 'args': args, 'image': image, 'trace': True})
        with (cell / 'run.log').open('xb') as log:
            result = subprocess.run(args, cwd=source, env=dict(env, VPNCTL_VM_RACE='1', VPNCTL_VM_CPUS='2',
                VPNCTL_TEST_BINARY=str(binary), VPNCTL_VM_IMAGE=image, VPNCTL_ARTIFACT_DIR=str(cell / 'results'),
                GOFLAGS='-overlay=' + str(overlay)), stdout=log, stderr=subprocess.STDOUT,
                preexec_fn=lambda: os.umask(0o022))
        status = {'index': index, 'exit': result.returncode}
        write(cell / 'exit.json', status)
        write(cell / 'kvm-after.json', kvm_snapshot())
        return status

    results = schedule(invoke)
    write(root / 'complete.json', {'qualification': False, 'cells': results})
    return int(any(row['exit'] for row in results))


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(run(Path(os.environ['VPNCTL_TRACE_ROOT']).resolve()))

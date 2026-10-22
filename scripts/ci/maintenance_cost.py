"""Private maintenance CPU attribution with unchanged capacity tests and gates."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from packet_trace import clone_source, require_disposable, write
from kvm_access import prepare_kvm, kvm_snapshot

REPO = Path(__file__).resolve().parents[2]
BASELINE = '89e1501e1a3584736ede2b1b56f5a160bc908e46'
DIAGNOSTIC = '50581d95bc5a0fd9d433fd4b2df583f7c39ca320'
CELLS = ('baseline', 'diagnostic', 'diagnostic', 'baseline')
CHANGES = {
    'internal/relayapply/node_lease.go', 'internal/relayapply/deployment_lease_staged.go',
    'internal/relayguard/guard_linux.go', 'internal/relayapply/node_lease_diagnostics_test.go',
    'internal/relayguard/diagnostics_linux_test.go', 'docs/testing/maintenance-cost-diagnostics.md',
    'internal/relayobserve/diagnostics.go', 'internal/relayobserve/phase_cpu.go',
    'internal/relayobserve/phase_cpu_test.go',
}


def schedule(invoke):
    return [invoke(index, mode) for index, mode in enumerate(CELLS, 1)]


def check_build(info, revision):
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
    for key, value in {'-race': 'true', 'GOOS': 'linux', 'GOARCH': 'amd64',
                       'vcs.revision': revision, 'vcs.modified': 'false'}.items():
        if settings.get(key) != value:
            raise ValueError('product identity/race setting differs')


def cell_args():
    return ['./scripts/test-vm.sh', '--case', 'application-capacity-8',
            '--robot-cpus', '1', '--cpu-layout', 'split']


def run(root):
    require_disposable()
    changes = subprocess.check_output(['git', '-C', str(REPO), 'diff', '--name-only',
                                      BASELINE, DIAGNOSTIC], text=True).splitlines()
    if set(changes) != CHANGES:
        raise ValueError('unexpected diagnostic change')
    env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='')
    products = {}
    for mode, revision in (('baseline', BASELINE), ('diagnostic', DIAGNOSTIC)):
        source = root / mode
        clone_source(REPO, source, revision)
        if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']).strip():
            raise ValueError('dirty fixed source')
        for module in ('main', 'probe', 'transport', 'vpnctl_uplink', 'echo_server'):
            if not (source / 'examples/uplink/python' / (module + '.py')).stat().st_mode & 0o004:
                raise ValueError('cap-free image builder cannot read Python input')
        binary = root / ('vpnctl-' + mode)
        subprocess.run(['go', 'build', '-p=2', '-race', '-o', str(binary), './cmd/vpnctl'],
                       cwd=source, env=env, check=True, timeout=1200)
        binary.chmod(0o755)
        info = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
        check_build(info, revision)
        with binary.open('rb') as data:
            products[mode] = {'revision': revision, 'sha256': hashlib.file_digest(data, 'sha256').hexdigest(),
                              'build_info': info}
    write(root / 'product.json', products)
    write(root / 'protocol.json', {'baseline': BASELINE, 'diagnostic': DIAGNOSTIC, 'suite': BASELINE,
        'controller': subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
        'race': True, 'cells': list(CELLS), 'robot_cpus': 1, 'server_cpus': 1, 'outer_cpus': 2,
        'qualification': False, 'host_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'host_affinity': sorted(os.sched_getaffinity(0)), 'host_kernel': os.uname().release})
    source = root / 'baseline'
    subprocess.run(['docker', 'build', '--cpu-period=100000', '--cpu-quota=100000', '--memory=2g',
        '--iidfile', str(root / 'image-id'), '-f', 'tests/vm/Dockerfile', 'tests/vm'], cwd=source,
        env=dict(env, DOCKER_BUILDKIT='0'), check=True, timeout=2400)
    image = (root / 'image-id').read_text().strip()
    (root / 'runs').mkdir()

    def invoke(index, mode):
        cell = root / 'runs' / f'{index:02}'
        cell.mkdir()
        prepare_kvm(cell)
        args = cell_args()
        write(cell / 'invocation.json', {'index': index, 'mode': mode, 'args': args, 'image': image,
                                        'product': products[mode]})
        with (cell / 'run.log').open('xb') as log:
            result = subprocess.run(args, cwd=source, env=dict(env, VPNCTL_VM_RACE='1', VPNCTL_VM_CPUS='2',
                VPNCTL_TEST_BINARY=str(root / ('vpnctl-' + mode)), VPNCTL_VM_IMAGE=image,
                VPNCTL_ARTIFACT_DIR=str(cell / 'results')), stdout=log, stderr=subprocess.STDOUT,
                preexec_fn=lambda: os.umask(0o022))
        status = {'index': index, 'mode': mode, 'exit': result.returncode}
        write(cell / 'exit.json', status)
        write(cell / 'kvm-after.json', kvm_snapshot())
        return status

    results = schedule(invoke)
    write(root / 'complete.json', {'qualification': False, 'cells': results})
    return int(any(row['exit'] for row in results))


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(run(Path(os.environ['VPNCTL_TRACE_ROOT']).resolve()))

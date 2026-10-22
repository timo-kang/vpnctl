"""Diagnostic branch only: unchanged capacity gates, fixed race cohort, private evidence."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from kvm_access import prepare_kvm, kvm_snapshot

REPO = Path(__file__).resolve().parents[2]
SOURCE = 'ec44c012b3ffb9629a302600fccbd28b05b591c1'
CELLS = (False, True, True, False)


def write(path, value):
    with path.open('x') as out:
        json.dump(value, out, indent=2)
        out.write('\n')


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('fixed source patch anchor differs')
    return text.replace(old, new)


def prepare_overlay(source, root):
    relative = 'tests/integration/m3_observation_capacity_test.go'
    text = (source / relative).read_text()
    text = replace_once(text, '\tf := build(t, paths, groupFD, results, initial)\n',
                        '\tf := build(t, paths, groupFD, results, initial)\n\tprivatePacketTrace(t, f, report)\n')
    replacement = root / 'capacity.go'
    replacement.write_text(text)
    overlay = root / 'overlay.json'
    write(overlay, {'Replace': {
        str(source / relative): str(replacement),
        str(source / 'tests/integration/private_packet_trace_test.go'):
            str(REPO / 'scripts/ci/private_packet_trace_test.go'),
    }})
    return overlay


def prepare_context(source, root):
    context = root / 'vm-context'
    shutil.copytree(source / 'tests/vm', context)
    agent = context / 'guest_agent.py'
    agent.write_text(replace_once(agent.read_text(),
        "                    if action == 'application-capacity-start':\n",
        "                    if action == 'application-capacity-start':\n"
        "                        if type(req.get('private_trace', False)) is not bool:\n"
        "                            raise ValueError('private_trace must be boolean')\n"
        "                        env['VPNCTL_PRIVATE_TRACE'] = '1' if req.get('private_trace', False) else '0'\n"))
    observer = context / 'observer.py'
    text = replace_once(observer.read_text(),
        "def exercise(vm, case, mode, delta, result, robot_cpus='0.5', cpu_layout='shared', uplink_api=False):",
        "def exercise(vm, case, mode, delta, result, robot_cpus='0.5', cpu_layout='shared', uplink_api=False, private_trace=False):")
    anchor = "        request = {'paths': paths, 'robot_cpus': robot_cpus, 'cpu_layout': cpu_layout, 'rebuild': preparation} if capacity else {}\n"
    text = replace_once(text, anchor, anchor + "        if capacity and private_trace:\n            request['private_trace'] = True\n")
    text = replace_once(text, "    parser.add_argument('--uplink-api-load', action='store_true')\n",
        "    parser.add_argument('--uplink-api-load', action='store_true')\n"
        "    parser.add_argument('--private-packet-trace', action='store_true')\n")
    text = replace_once(text, 'exercise(vm, case, mode, delta, verdict, args.robot_cpus, args.cpu_layout, args.uplink_api_load)',
        'exercise(vm, case, mode, delta, verdict, args.robot_cpus, args.cpu_layout, args.uplink_api_load, args.private_packet_trace)')
    observer.write_text(text)
    # These child files enter a cap-free image; the private parent stays 0700.
    for path in context.rglob('*'):
        if path.is_file():
            path.chmod(0o755 if path.suffix == '.sh' else 0o644)
    return context


def require_disposable():
    if any(os.environ.get(k) != v for k, v in {
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_RUN_ATTEMPT': '1',
    }.items()):
        raise RuntimeError('fresh disposable GitHub runner required; reruns are not trials')


def schedule(invoke):
    results = []
    for index, trace in enumerate(CELLS, 1):
        results.append(invoke(index, trace))
    return results


def clone_source(repository, source, revision):
    # Keep the parent private; child source files must retain normal read modes
    # when the original script copies Python modules to a cap-free UID0 builder.
    subprocess.run(['git', 'clone', '--no-hardlinks', '--no-checkout', str(repository), str(source)],
                   check=True, preexec_fn=lambda: os.umask(0o022))
    subprocess.run(['git', '-C', str(source), 'checkout', '--detach', revision],
                   check=True, preexec_fn=lambda: os.umask(0o022))


def run(root):
    require_disposable()
    source = root / 'source'
    clone_source(REPO, source, SOURCE)
    for module in ('main', 'probe', 'transport', 'vpnctl_uplink', 'echo_server'):
        if not (source / 'examples/uplink/python' / (module + '.py')).stat().st_mode & 0o004:
            raise ValueError('cap-free image builder cannot read Python input')
    if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']).strip():
        raise ValueError('dirty fixed source')
    write(root / 'protocol.json', {'source': SOURCE, 'controller': subprocess.check_output(
        ['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip(),
        'race': True, 'cells': list(CELLS), 'robot_cpus': 1, 'server_cpus': 1,
        'outer_cpus': 2, 'qualification': False, 'original_run': '39699878690',
        'host_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'host_affinity': sorted(os.sched_getaffinity(0)),
        'host_kernel': os.uname().release})
    binary = root / 'vpnctl'
    env = dict(os.environ, GOMAXPROCS='2')
    subprocess.run(['go', 'build', '-p=2', '-race', '-o', str(binary), './cmd/vpnctl'],
                   cwd=source, env=env, check=True, timeout=1200)
    binary.chmod(0o755)
    info = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
    if ('vcs.revision=' + SOURCE not in info or 'vcs.modified=false' not in info or '-race=true' not in info):
        raise ValueError('product identity/race setting differs')
    (root / 'product-build-info.txt').write_text(info)
    with binary.open('rb') as data:
        write(root / 'product.json', {'sha256': hashlib.file_digest(data, 'sha256').hexdigest()})
    overlay = prepare_overlay(source, root)
    context = prepare_context(source, root)
    subprocess.run(['python3', '-B', '-m', 'unittest', 'discover', '-s', str(context), '-p', 'test_*.py'],
                   check=True, timeout=120)
    subprocess.run(['docker', 'build', '--cpu-period=100000', '--cpu-quota=100000', '--memory=2g',
        '--iidfile', str(root / 'image-id'), '-f', str(context / 'Dockerfile'), str(context)],
        env=dict(env, DOCKER_BUILDKIT='0'), check=True, timeout=2400)
    image = (root / 'image-id').read_text().strip()
    (root / 'runs').mkdir()

    def invoke(index, trace):
        cell = root / 'runs' / f'{index:02}'
        cell.mkdir()
        prepare_kvm(cell)
        output = cell / 'results'
        args = ['./scripts/test-vm.sh', '--case', 'application-capacity-8', '--robot-cpus', '1', '--cpu-layout', 'split']
        if trace:
            args.append('--private-packet-trace')
        write(cell / 'invocation.json', {'index': index, 'trace': trace, 'args': args, 'image': image})
        with (cell / 'run.log').open('xb') as log:
            # Original script retains each worker failure and its private VM image.
            result = subprocess.run(args, cwd=source, env=dict(env, VPNCTL_VM_RACE='1', VPNCTL_VM_CPUS='2',
                VPNCTL_TEST_BINARY=str(binary), VPNCTL_VM_IMAGE=image, VPNCTL_ARTIFACT_DIR=str(output),
                GOFLAGS='-overlay=' + str(overlay)), stdout=log, stderr=subprocess.STDOUT,
                preexec_fn=lambda: os.umask(0o022))
        status = {'index': index, 'trace': trace, 'exit': result.returncode}
        write(cell / 'exit.json', status)
        write(cell / 'kvm-after.json', kvm_snapshot())
        return status

    results = schedule(invoke)
    write(root / 'complete.json', {'qualification': False, 'cells': results})
    return int(any(row['exit'] for row in results))


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(run(Path(os.environ['VPNCTL_TRACE_ROOT']).resolve()))

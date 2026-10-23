"""Exact-anchor test instrumentation; product and acceptance code stay unchanged."""
import hashlib
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('fixed source anchor differs: ' + old[:80])
    return text.replace(old, new, 1)


def prepare(source, root):
    target = root / 'overlay'
    target.mkdir()
    replacements = {}
    for name in ('m3_topology_test.go', 'm3_observation_capacity_test.go'):
        text = (source / 'tests/integration' / name).read_text()
        if name == 'm3_topology_test.go':
            text = once(text, 'type m3TCPTrace struct {\n',
                        'type m3TCPTrace struct {\n\tPID int `json:"private_pid"`\n')
            text = once(text, '&m3TCPTrace{StartedAt: began}',
                        '&m3TCPTrace{StartedAt: began, PID: os.Getpid()}')
        else:
            anchor = '\tf := build(t, paths, groupFD, results, initial)\n'
            text = once(text, anchor, anchor + '\tprivatePassiveTrace(t, f, report)\n')
            for address in ('"198.18.0.3"', 'm3Target', 'target'):
                text = once(text, f'applicationPayload(t, f, {address})',
                            f'privatePayload(t, f, {address}, report)')
        (target / name).write_text(text)
        replacements[str(source / 'tests/integration' / name)] = str(target / name)
    for name in ('private_passive_test.go', 'private_passive_metadata_test.go'):
        replacements[str(source / 'tests/integration' / name)] = str(HERE / name)
    overlay = root / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': replacements}, indent=2))
    return overlay, {k: hashlib.sha256(Path(v).read_bytes()).hexdigest() for k, v in replacements.items()}


def prepare_context(source, root):
    context = root / 'vm-context'
    shutil.copytree(source / 'tests/vm', context)
    agent = context / 'guest_agent.py'
    text = once(agent.read_text(), "                    if action == 'application-capacity-start':\n",
                "                    if action == 'application-capacity-start':\n"
                "                        env['VPNCTL_PRIVATE_TRACE'] = Path('/opt/vpnctl-diag/mode').read_text().strip()\n")
    text = once(text,
        "                result = {'exit': WORKER.poll()}\n                if result['exit'] is not None:\n                    # Keep the actual test assertion",
        "                result = {'exit': WORKER.poll()}\n                if result['exit'] is not None:\n"
        "                    if action == 'application-capacity-result':\n"
        "                        # After the worker exits, persist its report before QEMU stops.\n"
        "                        os.sync()\n                    # Keep the actual test assertion")
    agent.write_text(text)
    diag = context / 'passive'
    diag.mkdir()
    for name in ('guest.py', 'perf_events.py', 'process_memory.py', 'extract.py',
                 'export_contract.py', 'outer_guard.py', 'run_observer.py', 'analyze.py', 'correlate.py'):
        shutil.copyfile(HERE / 'passive' / name, diag / name)
    (diag / 'mode').write_text('1\n')
    dockerfile = context / 'Dockerfile'
    text = once(dockerfile.read_text(), 'COPY guest_agent.py /opt/vpnctl-vm/guest_agent.py\n',
                'COPY guest_agent.py /opt/vpnctl-vm/guest_agent.py\nCOPY passive/ /opt/vpnctl-diag/\n')
    text = once(text, 'COPY observer.py /opt/vpnctl-vm/observer.py\n',
                'COPY observer.py /opt/vpnctl-vm/observer.py\nCOPY passive/ /opt/vpnctl-diag/\n')
    text = once(text, 'ENTRYPOINT ["python3", "/opt/vpnctl-vm/observer.py"]',
                'ENTRYPOINT ["python3", "/opt/vpnctl-diag/run_observer.py"]')
    dockerfile.write_text(text)
    for path in context.rglob('*'):
        if path.is_file():
            path.chmod(0o755 if path.suffix == '.sh' else 0o644)
    return context

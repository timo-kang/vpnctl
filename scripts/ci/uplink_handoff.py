#!/usr/bin/env python3
"""Fixed-source integration qualification; detailed evidence stays encrypted."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import traceback

from isolated_evidence import (checked_source, digest, prepare_kvm, read_command,
                              require_disposable_runner, work_directories, write_json)

SOURCE = '2fd9b52858ea95a8505833fab78b428c49344dc9'
BINARIES = {'vpnctl', 'integration.test', 'vpnctl-legacy', 'vpnctl-lease-v1',
            'vpnctl-lease-v2', 'uplink-go'} | {
    'uplink-python/' + name + '.py' for name in
    ('main', 'probe', 'transport', 'vpnctl_uplink', 'echo_server')}


def schedule():
    profiles = [('application-capacity-4', 'split', False),
                ('application-capacity-4', 'split', True),
                ('application-capacity-8', 'split', True),
                ('application-capacity-8', 'split', False),
                ('application-capacity-rebuild-8', 'split', False),
                ('application-capacity-rebuild-8', 'split', True),
                ('application-capacity-8', 'shared', True),
                ('application-capacity-8', 'shared', False),
                ('uplink-apps-4', 'split', False), ('uplink-apps-8', 'split', False)]
    return [dict(sequence=i, case=case, layout=layout, api_load=load,
                 outer_cpus='2' if layout == 'split' else '1', robot_cpus='0.5')
            for i, (case, layout, load) in enumerate(profiles, 1)]


def arguments(row):
    args = ['--case', row['case'], '--robot-cpus', row['robot_cpus'],
            '--cpu-layout', row['layout']]
    return args + (['--uplink-api-load'] if row['api_load'] else [])


def execute_schedule(root, invoke):
    results = []
    for row in schedule():
        destination = root / f"run-{row['sequence']:02d}"
        destination.mkdir(mode=0o700)
        (destination / 'artifacts').mkdir(mode=0o700)
        record = dict(row, started_monotonic_ns=time.monotonic_ns())
        write_json(destination / 'invocation.json', record)
        try:
            record['exit_code'] = invoke(row, destination)
        except Exception as error:
            record.update(exit_code=125, infrastructure_error=type(error).__name__)
            (destination / 'infrastructure-error.log').write_text(traceback.format_exc())
        record['finished_monotonic_ns'] = time.monotonic_ns()
        write_json(destination / 'invocation.json', record)
        results.append(record)
        write_json(root / 'progress.json', results)
    passed = all(row['exit_code'] == 0 for row in results)
    write_json(root / 'complete.json', dict(invocations=len(results), all_exit_zero=passed))
    return 0 if passed else 1


def prepared_image(root, destination, before):
    created = {name: identity for name, identity in work_directories().items() if name not in before}
    write_json(destination / 'work-ownership.json', dict(before=before, created=created))
    if len(created) != 1:
        raise ValueError('one_private_image_work_directory_required')
    name, identity = next(iter(created.items()))
    work = Path(name)
    st = work.lstat()
    if (not re.fullmatch(r'/tmp/vpnctl-vm\.[A-Za-z0-9_]{6,16}', name)
            or not work.is_dir() or work.is_symlink() or work.resolve() != work
            or (st.st_dev, st.st_ino) != tuple(identity)
            or st.st_uid != os.getuid() or st.st_mode & 0o777 != 0o700):
        raise ValueError('private_image_ownership_invalid')
    manifests = list((destination / 'artifacts').glob('run-*.txt'))
    if len(manifests) != 1:
        raise ValueError('image_manifest_missing_or_ambiguous')
    fields = dict(line.split('=', 1) for line in manifests[0].read_text().splitlines() if '=' in line)
    if fields.get('suite_commit') != SOURCE or fields.get('suite_dirty') != 'false' or fields.get('suite_race') != '1':
        raise ValueError('initial_source_or_build_mismatch')
    image = fields.get('image_id', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('immutable_container_image_required')
    metadata = json.loads((work / 'image/image.json').read_text())
    if set(metadata['sha256']) != {'vmlinuz', 'initrd', 'guest.qcow2'} or set(metadata['binaries']) != BINARIES:
        raise ValueError('guest_manifest_members_invalid')
    prepared = dict(work=str(work), identity=identity, image_id=image, image=metadata)
    verify_image(prepared)
    for name, expected in metadata['binaries'].items():
        binary = work / 'input' / name
        if not binary.is_file() or binary.is_symlink() or digest(binary) != expected:
            raise ValueError('binary_digest_mismatch')
        target = root / 'binaries' / expected
        if not target.exists():
            shutil.copyfile(binary, target)
        if digest(target) != expected:
            raise ValueError('retained_binary_digest_mismatch')
    write_json(root / 'prepared.json', prepared)
    return prepared


def verify_image(prepared):
    work = Path(prepared['work'])
    st = work.lstat()
    if work.is_symlink() or (st.st_dev, st.st_ino) != tuple(prepared['identity']):
        raise ValueError('private_image_directory_changed')
    if json.loads((work / 'image/image.json').read_text()) != prepared['image']:
        raise ValueError('guest_manifest_changed')
    for name, expected in prepared['image']['sha256'].items():
        path = work / 'image' / name
        if not path.is_file() or path.is_symlink() or digest(path) != expected:
            raise ValueError('guest_image_changed')


def validate_trial(destination, row, prepared, exit_code):
    artifacts = destination / 'artifacts'
    evidence = artifacts / 'runner.json'
    if evidence.exists():
        runner = json.loads(evidence.read_text())
        if (runner['image'] != prepared['image'] or runner['cpu_layout'] != row['layout']
                or runner['guest_vcpus'] != int(row['outer_cpus'])
                or int(runner['cpu_max'][0]) != int(row['outer_cpus']) * int(runner['cpu_max'][1])):
            raise ValueError('trial_image_or_cpu_drift')
    elif exit_code == 0:
        raise ValueError('successful_trial_missing_runner_evidence')
    if exit_code == 0:
        verdicts = json.loads((artifacts / 'verdicts.json').read_text())
        if (len(verdicts) != 1 or verdicts[0].get('case') != row['case']
                or verdicts[0].get('completed') is not True or verdicts[0].get('qualified') is not True):
            raise ValueError('successful_trial_not_qualified')


def container_command(row, destination, prepared, name, runtime):
    return ['docker', 'run', '--rm', '--name', name, '--network', 'none',
            '--cpus', row['outer_cpus'], '--memory', '2g', '--memory-swap', '2g',
            '--pids-limit', '256', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--device', '/dev/kvm', '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
            '--user', f'{os.getuid()}:{os.getgid()}', '--group-add', str(Path('/dev/kvm').stat().st_gid),
            '--mount', f"type=bind,src={prepared['work']}/image,dst=/input,readonly",
            '--mount', f'type=bind,src={runtime},dst=/work',
            '--mount', f'type=bind,src={destination}/artifacts,dst=/results',
            prepared['image_id'], *arguments(row)]


def cleanup_runtime(runtime, container, log):
    # Only this invocation's named container and newly created runtime. Keep
    # disks if Docker cannot establish termination; never let old overlays bias
    # later trials through accumulating disk use after successful cleanup.
    subprocess.run(['docker', 'rm', '-f', container], stdout=log, stderr=subprocess.STDOUT, check=False)
    remaining = read_command(['docker', 'container', 'ls', '--all', '--filter',
                              'name=^/' + container + '$', '--format', '{{.ID}}'])
    if remaining:
        raise RuntimeError('owned_container_cleanup_unconfirmed')
    if runtime.is_symlink() or not runtime.is_dir():
        raise RuntimeError('owned_runtime_directory_changed')
    shutil.rmtree(runtime)


def main():
    require_disposable_runner()
    repo = Path(__file__).resolve().parents[2]
    root = Path(os.environ['VPNCTL_MATCHED_ROOT']).resolve()
    if (root / 'plan.json').exists() or not checked_source(repo, read_command(['git', 'rev-parse', 'HEAD'], repo)):
        raise RuntimeError('dirty_or_restarted_validation')
    (root / 'binaries').mkdir(mode=0o700)
    source = root / 'source-fixed'
    read_command(['git', 'worktree', 'add', '--detach', str(source), SOURCE], repo)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text()
    write_json(root / 'plan.json', dict(schema=1, source=SOURCE, schedule=schedule(),
        experiment_commit=read_command(['git', 'rev-parse', 'HEAD'], repo),
        plan_sha256=digest(repo / 'scripts/ci/PLAN.md'), runner_sha256=digest(Path(__file__)),
        github_run_id=os.environ['GITHUB_RUN_ID'], host_boot_id=boot.strip(),
        go_version=read_command(['go', 'version'])))
    shutil.copyfile(repo / 'scripts/ci/PLAN.md', root / 'PLAN.md')
    prepared = None

    def invoke(row, destination):
        nonlocal prepared
        if not checked_source(source, SOURCE) or Path('/proc/sys/kernel/random/boot_id').read_text() != boot:
            raise RuntimeError('source_or_host_boot_changed')
        prepare_kvm(destination)
        with (destination / 'runner.log').open('xb') as log:
            if row['sequence'] == 1:
                before = work_directories()
                env = dict(os.environ, GOMAXPROCS='2', VPNCTL_VM_CPUS=row['outer_cpus'],
                           VPNCTL_VM_RACE='1', VPNCTL_ARTIFACT_DIR=str(destination / 'artifacts'),
                           VPNCTL_KEEP_VM_WORK='1')
                for key in ('GOFLAGS', 'VPNCTL_TEST_BINARY', 'VPNCTL_VM_IMAGE', 'VPNCTL_VM_MANAGERS'):
                    env.pop(key, None)
                result = subprocess.run(['timeout', '-k', '30s', '35m', 'bash', 'scripts/test-vm.sh',
                                         *arguments(row)], cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
                write_json(destination / 'process-exit.json', dict(exit_code=result.returncode))
                prepared = prepared_image(root, destination, before)
                work = Path(prepared['work'])
                cleanup_runtime(work / 'runtime', 'vpnctl-vm-test-' + work.name.removeprefix('vpnctl-vm.'), log)
            else:
                if prepared is None:
                    raise RuntimeError('initial_image_unavailable_no_rebuild')
                verify_image(prepared)
                runtime = Path(prepared['work']) / f"runtime-{row['sequence']:02d}"
                runtime.mkdir(mode=0o700)
                name = 'vpnctl-uplink-' + os.environ['GITHUB_RUN_ID'] + '-' + str(row['sequence'])
                try:
                    result = subprocess.run(['timeout', '-k', '30s', '25m',
                        *container_command(row, destination, prepared, name, runtime)],
                        stdout=log, stderr=subprocess.STDOUT)
                    write_json(destination / 'process-exit.json', dict(exit_code=result.returncode))
                finally:
                    cleanup_runtime(runtime, name, log)
            write_json(destination / 'fixed-image.json', prepared)
            verify_image(prepared)
            validate_trial(destination, row, prepared, result.returncode)
            if Path('/proc/sys/kernel/random/boot_id').read_text() != boot:
                raise RuntimeError('host_boot_changed_during_trial')
            return result.returncode

    return execute_schedule(root, invoke)


if __name__ == '__main__':
    raise SystemExit(main())

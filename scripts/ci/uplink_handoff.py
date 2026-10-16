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

SOURCE = 'b58417a5da98c103cacce88af060c80b6c1142ff'
BINARIES = {'vpnctl', 'integration.test', 'vpnctl-legacy', 'vpnctl-lease-v1',
            'vpnctl-lease-v2', 'uplink-go'} | {
    'uplink-python/' + name + '.py' for name in
    ('main', 'probe', 'transport', 'vpnctl_uplink', 'echo_server')}


def schedule():
    # Same binary/image within each build; detailed child accounting is fixed ON.
    cells = [('1', False), ('0', False), ('0', True), ('1', True)]
    cells += list(reversed(cells))
    return [dict(sequence=i, case='application-capacity-8', layout='split', api_load=False,
                 outer_cpus='2', robot_cpus='0.5', build_race=race, cost_details=True, runtime_costs=runtime)
            for i, (race, runtime) in enumerate(cells, 1)]


def binary_build_info(path, race):
    lines = read_command(['go', 'version', '-m', str(path)]).splitlines()
    if not lines or not re.fullmatch(r'.+: go[0-9]+\.[^ ]+', lines[0]):
        raise ValueError('Go_build_information_missing')
    settings = {}
    for line in lines[1:]:
        fields = line.strip().split('\t', 1)
        if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            if key in settings:
                raise ValueError('duplicate_Go_build_setting')
            settings[key] = value
    if (race not in ('0', '1') or (settings.get('-race') == 'true') != (race == '1')
            or settings.get('-race') not in (None, 'true', 'false')
            or settings.get('GOOS') != 'linux' or settings.get('GOARCH') != 'amd64'):
        raise ValueError('Go_build_mode_mismatch')
    return dict(version=lines[0].rsplit(': ', 1)[1], settings=settings)


def validate_build_pair(race, ordinary):
    if (race['build_race'] != '1' or ordinary['build_race'] != '0'
            or race['image_id'] != ordinary['image_id']
            or race['image']['kernel'] != ordinary['image']['kernel']):
        raise ValueError('build_pair_base_mismatch')
    for name in ('vmlinuz', 'initrd'):
        if race['image']['sha256'][name] != ordinary['image']['sha256'][name]:
            raise ValueError('build_pair_kernel_mismatch')
    for name in BINARIES:
        if name.startswith('uplink-python/') and race['image']['binaries'][name] != ordinary['image']['binaries'][name]:
            raise ValueError('build_pair_python_mismatch')
    for name in ('vpnctl', 'integration.test', 'uplink-go'):
        first, second = race['build_info'][name], ordinary['build_info'][name]
        # -race is the only allowed compiler setting difference. Legacy
        # migration fixtures use separate temporary paths and are not executed
        # by these cases; retain their hashes without claiming byte equality.
        settings = [{k: v for k, v in item['settings'].items() if k != '-race'}
                    for item in (first, second)]
        if (first['version'] != second['version'] or settings[0] != settings[1]
                or race['image']['binaries'][name] == ordinary['image']['binaries'][name]):
            raise ValueError('build_pair_compiler_mismatch')


def build_environment(row, artifacts, base_image=None):
    env = dict(os.environ, GOMAXPROCS='2', VPNCTL_VM_CPUS=row['outer_cpus'],
               VPNCTL_VM_RACE=row['build_race'], VPNCTL_ARTIFACT_DIR=str(artifacts),
               VPNCTL_KEEP_VM_WORK='1')
    for key in ('GOFLAGS', 'VPNCTL_TEST_BINARY', 'VPNCTL_VM_IMAGE', 'VPNCTL_VM_MANAGERS'):
        env.pop(key, None)
    if base_image is not None:
        env['VPNCTL_VM_IMAGE'] = base_image
    return env


def arguments(row):
    args = ['--case', row['case'], '--robot-cpus', row['robot_cpus'],
            '--cpu-layout', row['layout']]
    return args + (['--uplink-api-load'] if row['api_load'] else []) + (['--cost-details'] if row['cost_details'] else []) + (['--runtime-costs'] if row['runtime_costs'] else [])


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


def prepared_image(root, destination, before, race):
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
    if fields.get('suite_commit') != SOURCE or fields.get('suite_dirty') != 'false' or fields.get('suite_race') != race:
        raise ValueError('initial_source_or_build_mismatch')
    image = fields.get('image_id', '')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('immutable_container_image_required')
    metadata = json.loads((work / 'image/image.json').read_text())
    if set(metadata['sha256']) != {'vmlinuz', 'initrd', 'guest.qcow2'} or set(metadata['binaries']) != BINARIES:
        raise ValueError('guest_manifest_members_invalid')
    prepared = dict(work=str(work), identity=identity, image_id=image, image=metadata,
                    build_race=race, build_info={name: binary_build_info(work / 'input' / name, race)
                    for name in ('vpnctl', 'integration.test', 'uplink-go')})
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
    write_json(root / ('prepared-race' + race + '.json'), prepared)
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
                or runner.get('cost_details') is not row['cost_details']
                or runner.get('runtime_costs') is not row['runtime_costs']
                or int(runner['cpu_max'][0]) != int(row['outer_cpus']) * int(runner['cpu_max'][1])):
            raise ValueError('trial_image_or_cpu_drift')
    elif exit_code == 0:
        raise ValueError('successful_trial_missing_runner_evidence')
    if exit_code == 0:
        verdicts = json.loads((artifacts / 'verdicts.json').read_text())
        diagnostic = row['case'].startswith('uplink-diag-')
        if (len(verdicts) != 1 or verdicts[0].get('case') != row['case']
                or verdicts[0].get('completed') is not True
                or verdicts[0].get('qualified') is not (not diagnostic)
                or (diagnostic and verdicts[0].get('unsupported_reason') != 'diagnostic_only_no_qualification')):
            raise ValueError('successful_trial_verdict_contract_invalid')


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
    images, attempted = {}, set()

    def invoke(row, destination):
        if not checked_source(source, SOURCE) or Path('/proc/sys/kernel/random/boot_id').read_text() != boot:
            raise RuntimeError('source_or_host_boot_changed')
        prepare_kvm(destination)
        with (destination / 'runner.log').open('xb') as log:
            race = row['build_race']
            if race not in attempted:
                attempted.add(race)  # Failed preparation is never rebuilt.
                if race == '0' and '1' not in images:
                    raise RuntimeError('shared_base_unavailable_no_independent_rebuild')
                before = work_directories()
                base = images['1']['image_id'] if race == '0' else None
                env = build_environment(row, destination / 'artifacts', base)
                result = subprocess.run(['timeout', '-k', '30s', '35m', 'bash', 'scripts/test-vm.sh',
                                         *arguments(row)], cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
                write_json(destination / 'process-exit.json', dict(exit_code=result.returncode))
                prepared = prepared_image(root, destination, before, race)
                images[race] = prepared
                work = Path(prepared['work'])
                cleanup_runtime(work / 'runtime', 'vpnctl-vm-test-' + work.name.removeprefix('vpnctl-vm.'), log)
            else:
                if race not in images:
                    raise RuntimeError('initial_image_unavailable_no_rebuild')
                prepared = images[race]
                verify_image(prepared)
                if len(images) == 2:
                    validate_build_pair(images['1'], images['0'])
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
            if len(images) == 2:
                validate_build_pair(images['1'], images['0'])
            verify_image(prepared)
            validate_trial(destination, row, prepared, result.returncode)
            if Path('/proc/sys/kernel/random/boot_id').read_text() != boot:
                raise RuntimeError('host_boot_changed_during_trial')
            return result.returncode

    return execute_schedule(root, invoke)


if __name__ == '__main__':
    raise SystemExit(main())

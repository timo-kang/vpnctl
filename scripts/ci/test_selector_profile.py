"""Profiler identity and mode controls without VM or host changes."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import uplink_handoff as runner


class SelectorProfileControls(unittest.TestCase):
    def test_fixed_runtime_counters_and_reversed_profile_intervention(self):
        rows = runner.schedule()
        cells = [(row['build_race'], row['selector_profile']) for row in rows]
        first = [('1', False), ('0', False), ('0', True), ('1', True)]
        self.assertEqual(cells, first + list(reversed(first)))
        for row in rows:
            self.assertIs(row['runtime_costs'], True)
            self.assertIs(row['cost_details'], True)
            self.assertEqual('--selector-profile' in runner.arguments(row), row['selector_profile'])
            self.assertEqual(runner.build_environment(row, '/results')['VPNCTL_VM_PROFILE'], '1')

    def test_actual_cli_tag_is_required_and_other_producers_cannot_be_tagged(self):
        plain = '/binary: go1.25.0\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n'
        for tagged in (False, True):
            for expected in (False, True):
                metadata = plain + ('\tbuild\t-tags=vpnctl_profile\n' if tagged else '')
                metadata += '\tbuild\tvcs.revision='+runner.SOURCE+'\n\tbuild\tvcs.modified=false\n'
                with mock.patch.object(runner, 'read_command', return_value=metadata):
                    if tagged == expected:
                        runner.binary_build_info('/binary', '0', profile=expected)
                    else:
                        with self.assertRaises(ValueError):
                            runner.binary_build_info('/binary', '0', profile=expected)

    def test_tagged_build_cannot_stamp_parent_worktree_or_dirty_source(self):
        metadata = ('/binary: go1.25.0\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n'
                    '\tbuild\t-tags=vpnctl_profile\n\tbuild\tvcs.revision='+runner.SOURCE+'\n\tbuild\tvcs.modified=false\n')
        for bad in (metadata.replace(runner.SOURCE, '0'*40),
                    metadata.replace('vcs.modified=false', 'vcs.modified=true'),
                    metadata.replace('\tbuild\tvcs.revision='+runner.SOURCE+'\n', '')):
            with mock.patch.object(runner, 'read_command', return_value=bad), self.assertRaises(ValueError):
                runner.binary_build_info('/binary', '0', profile=True)

    def test_source_checkout_uses_real_git_directory_and_exact_clean_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'source'
            source.mkdir(); (source/'.git').mkdir()
            with mock.patch.object(runner, 'read_command') as command, \
                 mock.patch.object(runner, 'checked_source', return_value=True) as checked:
                runner.prepare_source(Path('/repo'), source)
                self.assertEqual(command.call_args_list, [
                    mock.call(['git','clone','--no-checkout','--no-hardlinks','/repo',str(source)], Path('/repo')),
                    mock.call(['git','checkout','--detach',runner.SOURCE], source)])
                checked.assert_called_once_with(source,runner.SOURCE)
            (source/'.git').rmdir(); (source/'.git').write_text('gitdir: /another/worktree')
            with mock.patch.object(runner, 'read_command'), self.assertRaises(RuntimeError):
                runner.prepare_source(Path('/repo'), source)

    def test_recorded_profiler_mode_is_required_even_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); artifacts = root/'artifacts'; artifacts.mkdir()
            prepared = {'image': {'fixed': 'hash'}}
            for enabled in (False, True):
                row = dict(runner.schedule()[0], selector_profile=enabled)
                evidence = dict(image=prepared['image'], cpu_layout='split', guest_vcpus=2,
                                cpu_max=['200000', '100000'], cost_details=True, runtime_costs=True)
                (artifacts/'verdicts.json').write_text(json.dumps([dict(case=row['case'], completed=True, qualified=True)]))
                for change in ({}, {'selector_profile': None}, {'selector_profile': not enabled}, {'selector_profile': int(enabled)}):
                    (artifacts/'runner.json').write_text(json.dumps(dict(evidence, **change)))
                    for exit_code in (0, 1):
                        with self.subTest(change=change, exit_code=exit_code), self.assertRaises(ValueError):
                            runner.validate_trial(root, row, prepared, exit_code)
                (artifacts/'runner.json').write_text(json.dumps(dict(evidence, selector_profile=enabled)))
                runner.validate_trial(root, row, prepared, 0)

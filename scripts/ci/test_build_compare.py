"""Instrumented versus ordinary builds must remain a controlled comparison."""
import copy
import unittest
from unittest import mock

import uplink_handoff as runner


class BuildComparisonTests(unittest.TestCase):
    def test_predeclared_build_pairs_and_reverse_order(self):
        rows = runner.schedule()
        self.assertEqual(len(rows), 8)
        pairs = [(r['build_race'], r['selector_profile']) for r in rows]
        self.assertEqual(pairs[:4], [('1',False), ('0',False), ('0',True), ('1',True)])
        self.assertEqual(pairs[4:], list(reversed(pairs[:4])))
        self.assertTrue(all(r['case']=='application-capacity-8' for r in rows))
        for row in rows:
            self.assertIs(row['cost_details'], True)
            self.assertIn('--cost-details', runner.arguments(row))
            self.assertEqual('--runtime-costs' in runner.arguments(row), row['runtime_costs'])
        self.assertTrue(all(r['robot_cpus']=='0.5' and r['outer_cpus']=='2' and
                            r['layout']=='split' and r['api_load'] is False for r in rows))
        self.assertFalse(any(r.get('expected_injected_failure') for r in rows))

    def test_binary_build_information_rejects_mislabeled_race_build(self):
        plain = '/tmp/test: go1.26.2\n\tbuild\tGOARCH=amd64\n\tbuild\tGOOS=linux\n'
        race = plain + '\tbuild\t-race=true\n'
        with mock.patch.object(runner, 'read_command', return_value=plain):
            runner.binary_build_info('/tmp/test','0')
            with self.assertRaises(ValueError): runner.binary_build_info('/tmp/test','1')
        with mock.patch.object(runner, 'read_command', return_value=race):
            runner.binary_build_info('/tmp/test','1')
            with self.assertRaises(ValueError): runner.binary_build_info('/tmp/test','0')
        with mock.patch.object(runner, 'read_command', return_value='bad metadata'):
            with self.assertRaises(ValueError): runner.binary_build_info('/tmp/test','0')

    def test_paired_builds_reject_environment_and_shared_module_drift(self):
        first = dict(build_race='1',image_id='sha256:base',
            image=dict(kernel='fixed',sha256={'vmlinuz':'k','initrd':'i','guest.qcow2':'disk1'},
                       binaries={name:'same' for name in runner.BINARIES}),
            build_info={name:dict(version='go1.26.2',settings={'-race':'true','GOOS':'linux','GOARCH':'amd64'})
                        for name in ('vpnctl','integration.test','uplink-go')})
        second = copy.deepcopy(first);second['build_race']='0'
        second['image']['sha256']['guest.qcow2']='disk2'
        for name in second['build_info']:
            second['build_info'][name]['settings'].pop('-race')
            second['image']['binaries'][name]='ordinary'
        runner.validate_build_pair(first,second)
        mutations = [('image_id','different'), ('kernel','different'), ('initrd','different'),
                     ('module','different'), ('compiler','different'), ('binary','same')]
        for what,value in mutations:
            changed=copy.deepcopy(second)
            if what=='image_id': changed[what]=value
            elif what=='kernel': changed['image'][what]=value
            elif what=='initrd': changed['image']['sha256'][what]=value
            elif what=='module': changed['image']['binaries']['uplink-python/probe.py']=value
            elif what=='compiler': changed['build_info']['uplink-go']['version']=value
            else: changed['image']['binaries']['uplink-go']=value
            with self.subTest(what=what),self.assertRaises(ValueError):
                runner.validate_build_pair(first,changed)

    def test_ordinary_success_cannot_replace_original_qualification(self):
        import json
        import tempfile
        from pathlib import Path
        for case in ('application-capacity-8','uplink-apps-8'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'artifacts').mkdir()
                row=dict(runner.schedule()[0],case=case,build_race='0')
                prepared={'image':{'hash':'fixed'}}
                evidence=dict(image=prepared['image'],cpu_layout='split',guest_vcpus=2,cpu_max=['200000','100000'],cost_details=row['cost_details'],runtime_costs=row['runtime_costs'],selector_profile=row['selector_profile'])
                (root/'artifacts/runner.json').write_text(json.dumps(evidence))
                verdict=dict(case=case,completed=True,qualified=False)
                path=root/'artifacts/verdicts.json';path.write_text(json.dumps([verdict]))
                with self.assertRaises(ValueError): runner.validate_trial(root,row,prepared,0)
                verdict['qualified']=True;path.write_text(json.dumps([verdict]))
                runner.validate_trial(root,row,prepared,0)


    def test_recorded_detail_mode_cannot_be_missing_or_mislabeled(self):
        import json
        import tempfile
        from pathlib import Path
        for details in (False,True):
            with self.subTest(details=details),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);artifacts=root/'artifacts';artifacts.mkdir()
                row=dict(runner.schedule()[0],cost_details=details)
                prepared={'image':{'fixed':'hash'}}
                evidence=dict(image=prepared['image'],cpu_layout='split',guest_vcpus=2,cpu_max=['200000','100000'],runtime_costs=row['runtime_costs'],selector_profile=row['selector_profile'])
                (artifacts/'verdicts.json').write_text(json.dumps([dict(case=row['case'],completed=True,qualified=True)]))
                for value in (None,not details,1 if details else 0):
                    (artifacts/'runner.json').write_text(json.dumps(dict(evidence,cost_details=value)))
                    with self.assertRaises(ValueError): runner.validate_trial(root,row,prepared,0)
                (artifacts/'runner.json').write_text(json.dumps(dict(evidence,cost_details=details)))
                runner.validate_trial(root,row,prepared,0)

    def test_recorded_runtime_mode_cannot_be_missing_or_mislabeled(self):
        import json
        import tempfile
        from pathlib import Path
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); artifacts = root/'artifacts'; artifacts.mkdir()
                row = dict(runner.schedule()[0], runtime_costs=enabled)
                prepared = {'image': {'fixed': 'hash'}}
                evidence = dict(image=prepared['image'], cpu_layout='split', guest_vcpus=2,
                                cpu_max=['200000', '100000'], cost_details=True, selector_profile=row['selector_profile'])
                (artifacts/'verdicts.json').write_text(json.dumps([dict(case=row['case'], completed=True, qualified=True)]))
                for change in ({}, {'runtime_costs': None}, {'runtime_costs': not enabled}, {'runtime_costs': int(enabled)}):
                    (artifacts/'runner.json').write_text(json.dumps(dict(evidence, **change)))
                    for exit_code in (0, 1):
                        with self.subTest(change=change, exit_code=exit_code), self.assertRaises(ValueError):
                            runner.validate_trial(root, row, prepared, exit_code)
                (artifacts/'runner.json').write_text(json.dumps(dict(evidence, runtime_costs=enabled)))
                runner.validate_trial(root, row, prepared, 0)

    def test_build_environment_reuses_base_and_removes_external_overrides(self):
        row={'build_race':'0','outer_cpus':'2'}
        with mock.patch.dict(runner.os.environ, {'GOFLAGS':'-race','VPNCTL_TEST_BINARY':'/untrusted',
                'VPNCTL_VM_MANAGERS':'1','VPNCTL_VM_IMAGE':'mutable:tag'},clear=True):
            env=runner.build_environment(row,'/artifacts','sha256:fixed')
        self.assertEqual(env['VPNCTL_VM_RACE'],'0')
        self.assertEqual(env['VPNCTL_VM_IMAGE'],'sha256:fixed')
        self.assertNotIn('GOFLAGS',env);self.assertNotIn('VPNCTL_TEST_BINARY',env)
        self.assertNotIn('VPNCTL_VM_MANAGERS',env)


if __name__ == '__main__': unittest.main()

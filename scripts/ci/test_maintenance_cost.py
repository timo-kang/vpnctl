import unittest
import maintenance_cost as runner


class MaintenanceCostContract(unittest.TestCase):
    def test_fixed_schedule_preserves_failed_cell(self):
        seen = []
        def invoke(index, mode):
            seen.append((index, mode))
            return {'exit': 1 if index == 2 else 0}
        result = runner.schedule(invoke)
        self.assertEqual(seen, [(1, 'baseline'), (2, 'diagnostic'), (3, 'diagnostic'), (4, 'baseline')])
        self.assertEqual([x['exit'] for x in result], [0, 1, 0, 0])

    def test_original_one_cpu_split_case_without_overlays(self):
        self.assertEqual(runner.cell_args(), ['./scripts/test-vm.sh', '--case', 'application-capacity-8',
                                             '--robot-cpus', '1', '--cpu-layout', 'split'])
        self.assertNotEqual(runner.BASELINE, runner.DIAGNOSTIC)
        self.assertTrue(all(n.startswith(('internal/', 'docs/')) for n in runner.CHANGES))

    def test_product_build_requires_exact_clean_race_identity(self):
        info = ('vpnctl: go1.25.0\n\tbuild\t-race=true\n\tbuild\tGOOS=linux\n'
                '\tbuild\tGOARCH=amd64\n\tbuild\tvcs.revision=' + runner.BASELINE +
                '\n\tbuild\tvcs.modified=false\n')
        runner.check_build(info, runner.BASELINE)
        for old, new in [('go1.25.0', 'go1.22.2'), ('-race=true', '-race=false'),
                         ('GOOS=linux', 'GOOS=darwin'), ('GOARCH=amd64', 'GOARCH=arm64'),
                         (runner.BASELINE, runner.DIAGNOSTIC), ('vcs.modified=false', 'vcs.modified=true')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                runner.check_build(info.replace(old, new), runner.BASELINE)
        with self.assertRaises(ValueError):
            runner.check_build(info + '\tbuild\t-race=true\n', runner.BASELINE)


if __name__ == '__main__':
    unittest.main()

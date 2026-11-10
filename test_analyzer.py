#Integration tests for the original analyzer.py command-line program.

import csv
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ANALYZER = Path(__file__).with_name('analyzer.py')
HEADERS = ['timestamp', 'ip_address', 'username', 'status']


class SecurityAnalyzerTests(unittest.TestCase):
    def analyze(self, records, *options):
#Run the real script with temporary CSVs and return stdout and report rows
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / 'input.csv'
            output_file = Path(directory) / 'output.csv'
            with input_file.open('w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(HEADERS)
                writer.writerows(records)
            result = subprocess.run(
                [sys.executable, str(ANALYZER), '--file', str(input_file),
                 '--report', str(output_file), *options],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output_file.exists(), 'Report was not created')
            with output_file.open(newline='', encoding='utf-8') as file:
                rows = list(csv.DictReader(file))
            return result.stdout, {row['ip_address']: row for row in rows}

    def test_three_rapid_failures_are_high(self):
        records = [[f'2026-11-09 09:0{i}', '192.168.1.30', 'alice', 'Failed'] for i in range(3)]
        stdout, report = self.analyze(records)
        self.assertIn('3 failed logins within 5 minutes', stdout)
        self.assertEqual(report['192.168.1.30']['rapid_failures'], 'True')
        self.assertEqual(report['192.168.1.30']['risk_level'], 'HIGH')

    def test_slow_failures_are_medium(self):
        records = [[f'2026-11-09 09:{i:02d}', '192.168.1.150', 'alice', 'Failed'] for i in (0, 15, 30)]
        _, report = self.analyze(records)
        self.assertEqual(report['192.168.1.150']['rapid_failures'], 'False')
        self.assertEqual(report['192.168.1.150']['risk_level'], 'MEDIUM')

    def test_three_accounts_rapidly_targeted(self):
        records = [[f'2026-11-09 09:0{i}', '192.168.1.77', name, 'Failed']
                   for i, name in enumerate(('admin', 'alice', 'bob'))]
        stdout, report = self.analyze(records)
        self.assertIn('targeted 3 accounts within 5 minutes', stdout)
        self.assertEqual(report['192.168.1.77']['distinct_accounts'], '3')
        self.assertEqual(report['192.168.1.77']['multiple_accounts_targeted'], 'True')

    def test_three_accounts_spaced_out_not_flagged_as_multiple(self):
        records = [[f'2026-11-09 09:{i:02d}', '192.168.1.200', name, 'Failed']
                   for i, name in zip((0, 10, 20), ('admin', 'alice', 'bob'))]
        _, report = self.analyze(records)
        self.assertEqual(report['192.168.1.200']['multiple_accounts_targeted'], 'False')
        self.assertEqual(report['192.168.1.200']['risk_level'], 'MEDIUM')

    def test_midnight_and_unsorted_records(self):
        records = [[time, '192.168.1.210', 'admin', 'Failed'] for time in
                   ('2026-11-10 00:01', '2026-11-09 23:58', '2026-11-09 23:59')]
        _, report = self.analyze(records)
        self.assertEqual(report['192.168.1.210']['rapid_failures'], 'True')

    def test_exact_boundary_and_outside_window(self):
        inside = [[f'2026-11-09 09:{minute:02d}', '192.168.1.10', 'a', 'Failed']
                  for minute in (0, 2, 5)]
        outside = [[f'2026-11-09 09:{minute:02d}', '192.168.1.11', 'b', 'Failed']
                   for minute in (0, 2, 6)]
        _, report = self.analyze(inside + outside)
        self.assertEqual(report['192.168.1.10']['rapid_failures'], 'True')
        self.assertEqual(report['192.168.1.11']['rapid_failures'], 'False')

    def test_invalid_records_are_skipped(self):
        records = [
            ['2026-11-09 09:00', 'not-an-ip', 'a', 'Failed'],
            ['2026-11-09 09:00', '192.168.1.2', 'a', 'Unknown'],
            ['bad-time', '192.168.1.2', 'a', 'Failed'],
            ['2026-11-09 09:00', '192.168.1.2', '', 'Failed'],
            ['2026-11-09 09:00', '192.168.1.2', 'a', 'Success'],
        ]
        stdout, report = self.analyze(records)
        self.assertIn('5 records, 1 valid, 4 invalid', stdout)
        self.assertEqual(report, {})

    def test_custom_threshold_and_window(self):
        records = [[f'2026-11-09 09:{minute:02d}', '192.168.1.50', 'a', 'Failed']
                   for minute in (0, 2, 4, 9)]
        _, report = self.analyze(records, '--threshold', '4', '--window', '10')
        self.assertEqual(report['192.168.1.50']['rapid_failures'], 'True')
        _, report = self.analyze(records, '--threshold', '4', '--window', '5')
        self.assertEqual(report['192.168.1.50']['rapid_failures'], 'False')

    def test_account_threshold_is_independent(self):
        records = [[f'2026-11-09 09:0{i}', '192.168.1.77', name, 'Failed']
                   for i, name in enumerate(('admin', 'alice', 'bob'))]
        _, report = self.analyze(records, '--threshold', '4')
        self.assertEqual(report['192.168.1.77']['rapid_failures'], 'False')
        self.assertEqual(report['192.168.1.77']['multiple_accounts_targeted'], 'True')
        self.assertEqual(report['192.168.1.77']['risk_level'], 'HIGH')


if __name__ == '__main__':
    unittest.main()

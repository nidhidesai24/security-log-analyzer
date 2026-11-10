# Security Log Analyzer

A Python-based security monitoring tool that analyzes authentication logs to identify potentially suspicious login activity, detect unusual authentication patterns, and generate CSV security reports.

## Features

- **Failed Login Detection:** Identifies IP addresses with repeated failed authentication attempts.
- **Rapid Login Detection:** Detects multiple failed attempts within a configurable time window.
- **Multiple-Account Detection:** Identifies IP addresses attempting to access three or more different accounts within a specified time window.
- **Input Validation:** Checks IP addresses, timestamps, usernames, and login statuses.
- **Risk Classification:** Categorizes IP addresses as LOW, MEDIUM, or HIGH risk using predefined detection rules.
- **Customizable Settings:** Allows users to adjust detection thresholds, time windows, input files, and report filenames.
- **CSV Reporting:** Exports security findings for further investigation.
- **Automated Testing:** Includes nine tests covering detection logic, invalid records, and edge cases.

## Technologies

- Python 3
- CSV module
- datetime module
- ipaddress module
- argparse module
- unittest

## How to Run

Run the analyzer using the default settings:

```bash
python3 analyzer.py
```

Customize the failed-login threshold and time window:

```bash
python3 analyzer.py --threshold 4 --window 10
```

Specify a different input file or output report:

```bash
python3 analyzer.py --file custom_logs.csv --report custom_report.csv
```

## Input Format

The program accepts CSV files containing the following columns:

- `timestamp` — Date and time in YYYY-MM-DD HH:MM format
- `ip_address` — Source IP address
- `username` — Account associated with the login attempt
- `status` — Success or Failed

## Output

The program generates a CSV report containing:

- IP address
- Number of failed login attempts
- Number of distinct accounts targeted
- Rapid-failure detection status
- Multiple-account detection status
- Assigned risk level

Risk classifications are project-defined heuristics intended to help prioritize investigation, not definitive evidence of malicious activity.

## Testing

Run all automated tests:

```bash
python3 -m unittest -v
```

## Future Improvements

- Support additional authentication log formats
- Add visual dashboards for security trends
- Implement configurable risk-scoring rules
- Support larger log datasets efficiently
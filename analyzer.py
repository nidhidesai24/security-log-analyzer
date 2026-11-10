#import csv file
import csv
#handling date and time correctly
from datetime import datetime, timedelta
#validate ip address
import ipaddress
#allow the user to customize the analysis from the terminal
import argparse

#amount of failed attempts before warning appears
MAX_FAILED_ATTEMPTS = 3
TIME_WINDOW_MINUTES = 5

parser = argparse.ArgumentParser(description="Analyze login logs for suspicious activity")
parser.add_argument("--file", default="sample_logs.csv", help="CSV file to analyze")
parser.add_argument("--threshold", type=int, default=MAX_FAILED_ATTEMPTS, help="Number of failures to flag (minimum 2)")
parser.add_argument("--window", type=int, default=TIME_WINDOW_MINUTES, help="Time window in minutes (minimum 1)")
parser.add_argument("--report", default="security_report.csv", help="Output CSV report filename")
args = parser.parse_args()
if args.threshold < 2 or args.window < 1:
    parser.error("--threshold must be at least 2 and --window must be at least 1")

#stores amount of failed logins of each ip address
failed_attempts = {}
#stores timestamps of each failed login for each ip address
failed_times = {}
#stores (timestamp, username) for each failed login
failed_accounts = {}
valid_records = 0
invalid_records = 0
total_records = 0

# opens csv file and "r" puts it in reading mode
try:
    with open(args.file, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        required_columns = {"timestamp", "ip_address", "username", "status"}
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            parser.error("CSV must contain timestamp,ip_address,username,status columns")
# goes through each login record one at a time
        for row in reader:
            total_records += 1
#assigning ip address,status, timestamp and username without extra space before and after
            ip_address = (row.get("ip_address") or "").strip()
            status = (row.get("status") or "").strip()
            timestamp = (row.get("timestamp") or "").strip()
            username = (row.get("username") or "").strip()
#if ip address is empty print error
            if not ip_address:
                print("WARNING: Missing IP address")
                invalid_records += 1
                continue
#check validity of ip address and print warning if invalid
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                print("WARNING: Invalid IP address")
                invalid_records += 1
                continue
# if status value is not success or failed print warning
            if status != "Success" and status != "Failed":
                print("WARNING: Invalid login status")
                invalid_records += 1
                continue
            if not username:
                print("WARNING: Missing username")
                invalid_records += 1
                continue
#convert full timestamp into a datetime object (works across midnight)
            try:
                login_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M")
            except ValueError:
                print("ERROR: Invalid timestamp")
                invalid_records += 1
                continue
            valid_records += 1
#check for failed status
            if status == "Failed":
# checking if ip address exist in dictionary
                if ip_address in failed_attempts:
#if it does increment count by 1
                    failed_attempts[ip_address] += 1
                else:
#if it doesn't then add ip address to dictionary
                    failed_attempts[ip_address] = 1
#check if ip address is in failed times
                if ip_address not in failed_times:
#if it does not exist python needs to add a place to store this timestamp
                    failed_times[ip_address] = []
#add timestamp to failed times dictionary
                failed_times[ip_address].append(login_time)
#also record the username for multi-account detection
                if ip_address not in failed_accounts:
                    failed_accounts[ip_address] = []
                failed_accounts[ip_address].append((login_time, username))
#error if csv not found
except FileNotFoundError:
    parser.error(f"CSV file does not exist: {args.file}")

#warn if an IP has the configured number of failed login attempts
for ip_address, failed in failed_attempts.items():
    if failed >= args.threshold:
        print(f"WARNING: {ip_address} has {failed} failed login attempts")

#track which IPs have rapid failures or multiple accounts targeted
rapid_failure_ips = set()
multiple_account_ips = set()
#when the time on each ip address is greater than or equal to the threshold sort in chronological order
for ip_address, times in failed_times.items():
    if len(times) >= args.threshold:
        times.sort()
#check timestamps by groups of the chosen threshold
        for i in range(len(times) - args.threshold + 1):
            first_time = times[i]
            last_time = times[i + args.threshold - 1]
#calculate the time difference in minutes
            difference = last_time - first_time
            minutes = difference.total_seconds() / 60
#if time is inside the chosen window trigger warning
            if 0 <= minutes <= args.window:
                print(f"WARNING: {ip_address} had {args.threshold} failed logins within {args.window} minutes")
                rapid_failure_ips.add(ip_address)
                break

#detect one IP failing to log into 3 different accounts within the chosen window
for ip_address, events in failed_accounts.items():
    events.sort(key=lambda event: event[0])
    for i, (start_time, _) in enumerate(events):
        targeted_users = set()
        for login_time, username in events[i:]:
            if login_time - start_time > timedelta(minutes=args.window):
                break
            targeted_users.add(username)
            if len(targeted_users) >= 3:
                multiple_account_ips.add(ip_address)
                print(f"WARNING: {ip_address} targeted 3 accounts within {args.window} minutes")
                break
        if ip_address in multiple_account_ips:
            break

if not failed_attempts:
    print("No failed attempts found.")

#generate a CSV report with one row for each IP that had failed logins
report_rows = []
for ip_address, failed in failed_attempts.items():
    rapid = ip_address in rapid_failure_ips
    multiple = ip_address in multiple_account_ips
    distinct_accounts = len({username for _, username in failed_accounts[ip_address]})
#risk levels are project-defined heuristics, not proof of an attack
    if rapid or multiple:
        risk_level = "HIGH"
    elif failed >= args.threshold:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    report_rows.append({
        "ip_address": ip_address,
        "failed_attempts": failed,
        "distinct_accounts": distinct_accounts,
        "rapid_failures": rapid,
        "multiple_accounts_targeted": multiple,
        "risk_level": risk_level,
    })

report_rows.sort(key=lambda row: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[row["risk_level"]], -row["failed_attempts"], row["ip_address"]))
fieldnames = ["ip_address", "failed_attempts", "distinct_accounts", "rapid_failures", "multiple_accounts_targeted", "risk_level"]
with open(args.report, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(report_rows)

print(f"Analysis complete: {total_records} records, {valid_records} valid, {invalid_records} invalid.")
print(f"Security report saved to {args.report}")
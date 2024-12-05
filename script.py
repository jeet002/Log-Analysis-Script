import re
import csv
from collections import Counter, defaultdict

# Configuration constants
LOG_FILE = "sample.log"  # The log file to analyze
OUTPUT_FILE = "log_analysis_results.csv"  # File to store the analysis results
FAILED_LOGIN_THRESHOLD = (
    10  # Threshold for identifying suspicious activity based on failed logins
)


def parse_log_file(log_file):
    """Parses the log file and extracts relevant data like IP requests, endpoint requests, and failed logins."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    try:
        with open(log_file, "r") as file:
            for line in file:
                try:
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        ip_requests[ip] += 1

                    endpoint_match = re.search(r'"[A-Z]+\s+(/[^\s]*)\s+HTTP', line)
                    if endpoint_match:
                        endpoint = endpoint_match.group(1)
                        endpoint_requests[endpoint] += 1

                    if "401" in line or "Invalid credentials" in line:
                        if ip_match:
                            failed_logins[ip] += 1
                except Exception as e:
                    print(f"Error processing line: {line.strip()}. Error: {e}")

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"An unexpected error occurred while parsing the log file: {e}")

    return ip_requests, endpoint_requests, failed_logins


def output_results(ip_requests, most_accessed_endpoint, suspicious_ips, output_file):
    try:
        print("IP Address           Request Count")
        print("-" * 30)
        for ip, count in ip_requests.most_common():
            print(f"{ip:<20}{count}")

        print("\nMost Frequently Accessed Endpoint:")
        print(
            f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)"
        )

        print("\nSuspicious Activity Detected:")

        found_flagged_ip = False
        for ip, count in suspicious_ips:
            if count > FAILED_LOGIN_THRESHOLD and not found_flagged_ip:
                print(
                    "IP is flagged for suspicious activity due to failed login attempts exceeding the threshold (more than 10)."
                )
                found_flagged_ip = True
                print("IP Address           Failed Login Attempts")
                print("-" * 30)
            print(f"{ip:<20}{count}")
        if not found_flagged_ip:
            print(
                "IP has failed login attempts, but it is below the threshold (less than 10)."
            )

        with open(output_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_requests.items():
                writer.writerow([ip, count])

            writer.writerow([])
            writer.writerow(["Most Accessed Endpoint", "Access Count"])
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

            writer.writerow([])
            found_flagged_ip = False
            for ip, count in suspicious_ips:
                if count > FAILED_LOGIN_THRESHOLD and not found_flagged_ip:
                    writer.writerow(
                        [
                            "Flagged IPs",
                            "Failed login attempts exceed the threshold (more than 10).",
                        ]
                    )
                    found_flagged_ip = True
                    writer.writerow(["IP Address", "Failed Login Count"])
                writer.writerow([ip, count])
            if not found_flagged_ip:
                writer.writerow(
                    [
                        "Info",
                        "All IPs have failed login attempts below the threshold (less than 10).",
                    ]
                )
                writer.writerow(["IP Address", "Failed Login Count"])
                writer.writerow(["-", "-"])

    except Exception as e:
        print(f"An error occurred while writing results to the file: {e}")


def main():
    try:
        ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)

        if endpoint_requests:
            most_accessed_endpoint = endpoint_requests.most_common(1)[0]
        else:
            most_accessed_endpoint = ("None", 0)

        suspicious_ips = [
            (ip, count)
            for ip, count in failed_logins.items()
            if count > FAILED_LOGIN_THRESHOLD
        ]
        # suspicious_ips = [(ip, count) for ip, count in failed_logins.items()]

        output_results(ip_requests, most_accessed_endpoint, suspicious_ips, OUTPUT_FILE)
    except Exception as e:
        print(f"An unexpected error occurred in the main function: {e}")


if __name__ == "__main__":
    main()

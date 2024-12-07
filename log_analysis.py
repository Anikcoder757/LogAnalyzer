import re
import csv
from collections import defaultdict, Counter

def parse_log_file(file_path):
    ip_request_counts = Counter()
    endpoint_counts = Counter()
    failed_login_attempts = defaultdict(int)
    failed_login_threshold = 10  # Configurable threshold for brute force detection

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                continue
            ip_address = ip_match.group(1)
            ip_request_counts[ip_address] += 1

            # Extract endpoint
            endpoint_match = re.search(r'"(?:GET|POST) (\S+)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1

            # Detect failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                failed_login_attempts[ip_address] += 1

    return ip_request_counts, endpoint_counts, failed_login_attempts, failed_login_threshold

def save_to_csv(ip_request_counts, endpoint_counts, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_request_counts.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Write Most Accessed Endpoint
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoint_counts.items():
            writer.writerow([endpoint, count])

        writer.writerow([])  # Blank line

        # Write Suspicious Activity
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips:
            writer.writerow([ip, count])

def main():
    log_file = 'sample.log'  # Replace with your log file path
    output_file = 'log_analysis_results.csv'

    # Parse log file
    ip_request_counts, endpoint_counts, failed_login_attempts, threshold = parse_log_file(log_file)

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_counts.most_common(1)
    if most_accessed_endpoint:
        print(f"Most Frequently Accessed Endpoint:\n{most_accessed_endpoint[0][0]} (Accessed {most_accessed_endpoint[0][1]} times)")

    # Detect suspicious activity
    suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > threshold]
    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips:
            print(f"{ip:<20} {count:<20}")

    # Display Requests per IP
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<20}")
    for ip, count in ip_request_counts.most_common():
        print(f"{ip:<20} {count:<20}")

    # Save results to CSV
    save_to_csv(ip_request_counts, endpoint_counts, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()

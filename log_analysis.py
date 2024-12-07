import re
import csv
from collections import defaultdict

# Function to parse the log file
def parse_log_file(log_file):
    ip_requests = {}
    endpoint_access = {}
    failed_attempts = {}

    with open(log_file, 'r') as file:
        for line in file:
            # Extract relevant details from the log line using regular expressions
            match = re.match(r'(\S+) - - \[.*\] "(.*?)" \d+ \d+.*', line)
            if match:
                ip_address, request = match.groups()

                # Count requests per IP address
                ip_requests[ip_address] = ip_requests.get(ip_address, 0) + 1

                # Count endpoint access
                endpoint = request.split(" ")[1]
                endpoint_access[endpoint] = endpoint_access.get(endpoint, 0) + 1

                # Detect failed login attempts (HTTP status 401 or "Invalid credentials" message)
                if "POST /login" in request and ("401" in line or "Invalid credentials" in line):
                    failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1

    # Debug print the failed_attempts to see if we are capturing any failed logins
    print("Failed Attempts Data:", failed_attempts)

    return ip_requests, endpoint_access, failed_attempts


# Function to save results to a CSV file
def save_to_csv(ip_requests, most_accessed_endpoint, failed_attempts, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        writer.writerow([])

        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])

        # Write suspicious activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

# Main script
def main():
    log_file = "sample.log"  # Input log file
    output_file = "log_analysis_results.csv"  # Output CSV file
    threshold = 1  # Set the threshold to 1 for testing

    # Parse the log file
    ip_requests, endpoint_access, failed_attempts = parse_log_file(log_file)

    # Debug print the suspicious activity data
    print("Failed Attempts Data:", failed_attempts)

    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1])

    # Filter suspicious activity (IPs with failed attempts >= threshold)
    suspicious_activity = {ip: count for ip, count in failed_attempts.items() if count >= threshold}

    # Debug print for suspicious activity data
    print("Suspicious Activity Data:", suspicious_activity)

    # Display results in the terminal
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count:<15}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file)


# Run the script
if __name__ == "__main__":
    main()



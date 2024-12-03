import csv
from collections import defaultdict
import argparse

# Configure command-line arguments
parser = argparse.ArgumentParser(description="Log Analysis Script")
parser.add_argument('--threshold', type=int, default=10, help='Failed login threshold (default: 10)')
args = parser.parse_args()

# Threshold for failed login attempts
threshold = args.threshold

try:
    # Try to open and read the log file
    with open('sample.log', 'r') as file:
        lines = file.readlines()
    
    # Check if the file is empty
    if not lines:
        print("Error: The log file is empty. Please provide a valid log file.")
        exit(1)

except FileNotFoundError:
    print("Error: The log file 'sample.log' was not found. Please ensure the file exists in the project folder.")
    exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}")
    exit(1)

# Count requests per IP address
ip_count = defaultdict(int)
for line in lines:
    parts = line.split()
    if len(parts) < 9:  # Check for malformed lines
        continue
    ip = parts[0]
    ip_count[ip] += 1

# Print IP address counts
print(f"{'IP Address':<20} {'Request Count':<10}")
for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:<20} {count:<10}")

# Identify the most accessed endpoint
endpoint_count = defaultdict(int)
for line in lines:
    parts = line.split()
    if len(parts) < 9:  # Check for malformed lines
        continue
    endpoint = parts[6]
    endpoint_count[endpoint] += 1

if endpoint_count:
    most_accessed = max(endpoint_count, key=endpoint_count.get)
    print(f"\nMost Frequently Accessed Endpoint: {most_accessed} (Accessed {endpoint_count[most_accessed]} times)")
else:
    print("\nNo endpoints found in the log file.")

# Detect suspicious activity (failed login attempts)
failed_logins = defaultdict(int)
for line in lines:
    parts = line.split()
    if len(parts) < 9:  # Check for malformed lines
        continue
    status_code = parts[8]
    if status_code == '401':  # Detect failed login attempts
        ip = parts[0]
        failed_logins[ip] += 1

# Display suspicious activity
print("\nSuspicious Activity Detected:")
suspicious_data = [(ip, count) for ip, count in failed_logins.items() if count > threshold]
if suspicious_data:
    for ip, count in suspicious_data:
        print(f"{ip} - Failed Login Attempts: {count}")
else:
    print("No suspicious activity detected.")

# Save results to a CSV file
ip_data = [(ip, count) for ip, count in ip_count.items()]
endpoint_data = [(endpoint, count) for endpoint, count in endpoint_count.items()]

with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # Write IP request counts
    writer.writerow(['IP Address', 'Request Count'])
    writer.writerows(ip_data)
    
    # Write most accessed endpoint
    writer.writerow([])
    writer.writerow(['Most Accessed Endpoint'])
    if endpoint_count:
        writer.writerow([most_accessed, endpoint_count[most_accessed]])
    else:
        writer.writerow(['No endpoints found'])
    
    # Write suspicious activity
    writer.writerow([])
    writer.writerow(['Suspicious Activity IP Address', 'Failed Login Count'])
    if suspicious_data:
        writer.writerows(suspicious_data)
    else:
        writer.writerow(['No suspicious activity detected'])

print("\nResults saved to log_analysis_results.csv")

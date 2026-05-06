import subprocess
import sys
import os
import re

ALLOWED_PORTS = {
    9050, 9150, 1080, 8080, 3128, 8081, 8888, 9999,
    *range(1081, 1251)  # 1081 to 1250 inclusive
}

def scan_subdomains(file_path, output_dir="nmap results"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(file_path, 'r') as f:
        subdomains = f.read().splitlines()

    for subdomain in subdomains:
        print(f"Scanning {subdomain}...")
        output_file = os.path.join(output_dir, f"{subdomain}_scan.txt")

        # Primary scan (all TCP ports)
        result = subprocess.run(
            ["nmap", "-p-", subdomain],
            capture_output=True,
            text=True
        )

        # Fallback scan if primary fails
        if result.returncode != 0:
            print(f"Primary scan failed for {subdomain}, trying fallback...")
            result = subprocess.run(
                ["nmap", "-sS", "-Pn", "-sV", subdomain],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f"Fallback scan also failed for {subdomain}, skipping.")
                continue

        with open(output_file, 'w') as out_f:
            out_f.write(result.stdout)

        print(f"Saving scan in {output_file}")

        open_ports = set()

        for line in result.stdout.splitlines():
            match = re.search(r'(\d+)/tcp\s+open', line)
            if match:
                port = int(match.group(1))
                print(f"Open port found: {port} on {subdomain}")

                if port in ALLOWED_PORTS:
                    open_ports.add(port)

        if open_ports:
            print(f"Open ports found on: {subdomain}: {sorted(open_ports)}")
        else:
            print(f"No allowed ports found on: {subdomain}")

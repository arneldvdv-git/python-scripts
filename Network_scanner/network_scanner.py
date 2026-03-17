import subprocess
import socket
import ssl
from datetime import datetime, timedelta, timezone
import pandas as pd
import ipaddress
from cryptography import x509

# Function to add IP ranges or hostnames into a list of targets
def add_targets(targets):
    host_list = []
    for target in targets:
        target = target.strip()
        if '/' in target:  # Assume CIDR notation for ranges
            try:
                net = ipaddress.ip_network(target, strict=False)
                # Limit to first 10 hosts for large ranges to avoid excessive scanning
                hosts = list(net.hosts())[:10] if len(list(net.hosts())) > 10 else list(net.hosts())
                host_list.extend([str(ip) for ip in hosts])
            except ValueError:
                # If not a valid network, treat as hostname
                host_list.append(target)
        else:
            host_list.append(target)
    return host_list

# Function to perform DNS lookups (forward and reverse)
def get_dns_info(target):
    """
    If target is an IP, do reverse DNS lookup to get hostname
    If target is a hostname, do forward DNS lookup to get IP
    Returns: (ip_address, dns_name)
    """
    try:
        # Check if target is an IP address
        ipaddress.ip_address(target)
        # It's an IP address, do reverse DNS lookup
        ip_address = target
        try:
            dns_name = socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.error):
            dns_name = 'Unknown'
        return ip_address, dns_name
    except ValueError:
        # It's not an IP address, it's a hostname, do forward DNS lookup
        dns_name = target
        try:
            ip_address = socket.gethostbyname(dns_name)
        except (socket.gaierror, socket.error):
            ip_address = 'Unknown'
        return ip_address, dns_name

# Function to perform ping check using subprocess
def ping_host(host):
    try:
        # Use ping command; adjust for Windows (-n for count, -w for timeout in ms)
        result = subprocess.run(['ping', '-n', '1', '-w', '1000', host], 
                                capture_output=True, text=True, timeout=5)
        # Return True if ping succeeds (returncode 0)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

# Function to get SSL certificate expiry and issue dates
def get_ssl_expiry(host, port=443):
    # print(f"\n=== Starting SSL check for {host} ===")
    try:
        # First, try to resolve the hostname
        # print(f"[STEP 1] Resolving hostname...")
        try:
            resolved_ip = socket.gethostbyname(host)
            # print(f"[DEBUG] {host} resolved to {resolved_ip}")
        except socket.gaierror as e:
            # print(f"[DEBUG] Failed to resolve hostname: {host} - {e}")
            return None, None
        
        # Create SSL context that accepts any certificate
        # print(f"[STEP 2] Creating SSL context...")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # print(f"[DEBUG] SSL context created")
        
        # Try to connect with a longer timeout
        # print(f"[STEP 3] Attempting socket connection to {host}:{port}...")
        try:
            sock = socket.create_connection((host, port), timeout=10)
            # print(f"[DEBUG] Socket connection successful")
        except Exception as e:
            # print(f"[DEBUG] Socket connection failed: {type(e).__name__}: {e}")
            return None, None
        
        # print(f"[STEP 4] Wrapping socket with SSL...")
        try:
            ssock = context.wrap_socket(sock, server_hostname=host)
            # print(f"[DEBUG] SSL wrap successful")
        except Exception as e:
            # print(f"[DEBUG] SSL wrap failed: {type(e).__name__}: {e}")
            sock.close()
            return None, None
        
        # print(f"[STEP 5] Getting certificate (binary form)...")
        try:
            # Get certificate in binary form for proper parsing
            cert_bin = ssock.getpeercert(binary_form=True)
            # print(f"[DEBUG] Binary certificate retrieved: {cert_bin is not None}")
            
            if cert_bin is None:
                # print(f"[DEBUG] Binary certificate is None")
                # Also try non-binary form
                cert_dict = ssock.getpeercert()
                # print(f"[DEBUG] Non-binary certificate keys: {list(cert_dict.keys()) if cert_dict else 'None'}")
                ssock.close()
                return None, None
            
            # Parse the binary certificate using cryptography library
            # print(f"[STEP 6] Parsing binary certificate with cryptography...")
            try:
                cert = x509.load_der_x509_certificate(cert_bin)
                
                # Get notBefore and notAfter as datetime objects
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
                
                # print(f"[DEBUG] Certificate notBefore: {not_before}")
                # print(f"[DEBUG] Certificate notAfter: {not_after}")
                
                ssock.close()
                return not_before, not_after
                
            except Exception as e:
                print(f"[DEBUG] Failed to parse certificate: {type(e).__name__}: {e}")
                ssock.close()
                return None, None
                
        except Exception as e:
            print(f"[DEBUG] Certificate retrieval error: {type(e).__name__}: {e}")
            ssock.close()
            return None, None
                    
    except socket.timeout:
        print(f"[DEBUG] Connection timeout for {host}:{port}")
        return None, None
    except socket.error as e:
        print(f"[DEBUG] Socket error for {host}: {e}")
        return None, None
    except ssl.SSLError as e:
        print(f"[DEBUG] SSL error for {host}: {e}")
        return None, None
    except Exception as e:
        print(f"[DEBUG] Unexpected error for {host}: {type(e).__name__}: {e}")
        return None, None

# Main function to scan targets
def scan_targets(targets):
    results = []
    now = datetime.now(timezone.utc) + timedelta(hours=1)  # Adjust to local time (UTC+1)
    for target in targets:
        scan_time = now.strftime('%d-%m-%Y %H:%M:%S')
        
        # Get DNS information (IP address and hostname)
        ip_address, dns_name = get_dns_info(target)
        
        # Ping check
        ping_success = ping_host(target)
        status = 'online' if ping_success else 'offline'
        
        # SSL expiry check
        issue_date, expiry_date = get_ssl_expiry(target)
        if expiry_date:
            days_to_expiry = (expiry_date - now).days
            if days_to_expiry <= 30:
                ssl_expiry = f"{expiry_date.strftime('%d-%m-%Y')} WARNING (expires in {days_to_expiry} days)"
            else:
                ssl_expiry = expiry_date.strftime('%d-%m-%Y')
            ssl_issue = issue_date.strftime('%d-%m-%Y') if issue_date else 'Unknown'
        else:
            ssl_expiry = 'No certificate'
            ssl_issue = 'No certificate'
        
        # Collect result
        results.append({
            'target': target,
            'ip_address': ip_address,
            'dns_name': dns_name,
            'status': status,
            'ssl_issued': ssl_issue,
            'ssl_expiry': ssl_expiry,
            'last_scan_time': scan_time
        })
    return results

# Main execution
if __name__ == "__main__":
    try:
        # Read targets from targets.txt
        with open('targets.txt', 'r') as f:
            raw_targets = f.readlines()
        
        # Expand targets (handle ranges)
        targets = add_targets(raw_targets)
        
        # Scan targets
        results = scan_targets(targets)
        
        # Create DataFrame
        df = pd.DataFrame(results)
        
        # Export to CSV
        df.to_csv('inventory-report.csv', index=False)
        
        print("Scan completed. Results saved to inventory-report.csv")
    except FileNotFoundError:
        print("Error: targets.txt file not found. Please create it with IP ranges and/or hostnames.")
    except Exception as e:
        print(f"An error occurred: {e}")
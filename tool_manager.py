#!/usr/bin/env python3
"""
Tool Detection and Installation Manager
Handles checking for tool existence and automated installation
"""

import subprocess
import sys
import platform
import os
from pathlib import Path
import json

class ToolManager:
    def __init__(self):
        self.os_type = platform.system()
        self.distro = self._detect_distro()
        self.installed_tools = {}
        self.missing_tools = {}
        self.tool_database = self._load_tool_database()
        self._warned: set[str] = set()
        # Map orchestrator/ledger tool names to canonical binaries/packages
        self.tool_aliases = {
            # Ledger pseudo-tools → real binaries
            'nmap_quick': 'nmap',
            'nmap_vuln': 'nmap',
            'dig_a': 'dig',
            'dig_ns': 'dig',
            'dig_mx': 'dig',
            'nuclei_crit': 'nuclei',
            'nuclei_high': 'nuclei',
            # testssl binary name
            'testssl': 'testssl.sh',
        }
    
    def _detect_distro(self):
        """Detect Linux distribution"""
        if self.os_type == "Linux":
            try:
                result = subprocess.run(['lsb_release', '-si'], capture_output=True, text=True)
                return result.stdout.strip().lower()
            except:
                return "linux"
        return self.os_type.lower()
    
    def _load_tool_database(self):
        """Load tool database with installation information"""
        return {
            # DNS Tools
            'assetfinder': {
                'apt': None,  # Not available via apt on Kali
                'pip': None,
                'brew': 'tomnomnom/tap/assetfinder',
                'go': 'github.com/tomnomnom/assetfinder@latest',
                'custom': 'apt-get install -y golang-go 2>/dev/null && go install github.com/tomnomnom/assetfinder@latest && export PATH=$PATH:/root/go/bin',
                'category': 'DNS',
                'description': 'Subdomain discovery tool'
            },
            'dnsrecon': {
                'apt': 'dnsrecon',
                'pip': 'dnsrecon',
                'brew': 'dnsrecon',
                'category': 'DNS',
                'description': 'DNS enumeration tool'
            },
            'host': {
                'apt': 'bind-utils',
                'pip': None,
                'brew': 'bind',
                'category': 'DNS',
                'description': 'DNS lookup utility'
            },
            'dig': {
                'apt': 'dnsutils',
                'pip': None,
                'brew': 'bind',
                'category': 'DNS',
                'description': 'DNS lookup utility'
            },
            'nslookup': {
                'apt': 'bind-tools',
                'pip': None,
                'brew': 'bind',
                'category': 'DNS',
                'description': 'DNS lookup utility'
            },
            'dnsenum': {
                'apt': 'dnsenum',
                'pip': 'dnsenum',
                'brew': 'dnsenum',
                'category': 'DNS',
                'description': 'DNS enumeration tool'
            },
            
            # Network Tools
            'nmap': {
                'apt': 'nmap',
                'pip': None,
                'brew': 'nmap',
                'category': 'Network',
                'description': 'Network mapper and port scanner'
            },
            'traceroute': {
                'apt': 'traceroute',
                'pip': None,
                'brew': 'traceroute',
                'category': 'Network',
                'description': 'Trace network route'
            },
            'whois': {
                'apt': 'whois',
                'pip': 'python-whois',
                'brew': 'whois',
                'category': 'Network',
                'description': 'WHOIS lookup tool'
            },
            'ping': {
                'apt': 'iputils-ping',
                'pip': None,
                'brew': None,
                'category': 'Network',
                'description': 'Network ping utility'
            },
            
            # SSL/TLS Tools
            'testssl': {
                'apt': 'testssl.sh',
                'pip': None,
                'brew': 'testssl',
                'category': 'SSL/TLS',
                'description': 'SSL/TLS vulnerability scanner'
            },
            'sslscan': {
                'apt': 'sslscan',
                'pip': 'sslscan',
                'brew': 'sslscan',
                'category': 'SSL/TLS',
                'description': 'SSL configuration scanner'
            },
            'openssl': {
                'apt': 'openssl',
                'pip': None,
                'brew': 'openssl',
                'category': 'SSL/TLS',
                'description': 'SSL/TLS toolkit'
            },
            'sslyze': {
                'apt': 'sslyze',  # Now available via apt on Kali
                'pip': 'sslyze',
                'brew': None,
                'custom': 'apt-get install -y sslyze 2>/dev/null || (apt-get install -y pipx 2>/dev/null && pipx install sslyze && pipx ensurepath)',
                'category': 'SSL/TLS',
                'description': 'SSL/TLS analyzer'
            },
            
            # Web Scanning Tools
            'wpscan': {
                'apt': None,
                'pip': 'wpscan',
                'brew': 'wpscan',
                'category': 'Web',
                'description': 'WordPress vulnerability scanner'
            },
            'whatweb': {
                'apt': 'whatweb',
                'pip': 'whatweb',
                'brew': 'whatweb',
                'category': 'Web',
                'description': 'Web technology identifier'
            },
            'gobuster': {
                'apt': 'gobuster',
                'pip': None,
                'brew': 'gobuster',
                'category': 'Web',
                'description': 'Directory and DNS brute forcing tool'
            },
            'dirsearch': {
                'apt': 'dirsearch',
                'pip': 'dirsearch',
                'brew': None,
                'category': 'Web',
                'description': 'Web path scanner'
            },
            'nikto': {
                'apt': 'nikto',
                'pip': None,
                'brew': 'nikto',
                'category': 'Web',
                'description': 'Web server scanner'
            },
            # Vulnerability Scanners
            'xsstrike': {
                'apt': None,
                'pip': 'xsstrike',
                'brew': None,
                'category': 'Vulnerabilities',
                'description': 'XSS detection tool'
            },
            'dalfox': {
                'apt': None,
                'pip': None,
                'go': 'github.com/hahwul/dalfox/v2@latest',
                'brew': None,
                'custom': 'apt-get install -y golang-go 2>/dev/null && go install github.com/hahwul/dalfox/v2@latest && export PATH=$PATH:/root/go/bin',
                'category': 'Vulnerabilities',
                'description': 'XSS vulnerability scanner'
            },
            'xsser': {
                'apt': 'xsser',
                'pip': 'xsser',
                'brew': None,
                'category': 'Vulnerabilities',
                'description': 'XSS vulnerability scanner'
            },
            'commix': {
                'apt': None,
                'pip': 'commix',
                'brew': None,
                'category': 'Vulnerabilities',
                'description': 'Command injection tester'
            },
            'sqlmap': {
                'apt': 'sqlmap',
                'pip': 'sqlmap',
                'brew': 'sqlmap',
                'category': 'Vulnerabilities',
                'description': 'SQL injection tester'
            },
            'arjun': {
                'apt': None,
                'pip': 'arjun',
                'brew': None,
                'category': 'Vulnerabilities',
                'description': 'HTTP parameter discovery'
            },
            
            # Subdomain Tools
            'findomain': {
                'apt': None,  # Install from GitHub releases
                'pip': None,
                'go': None,  # Rust binary, use GitHub release
                'brew': 'findomain',
                'custom': 'wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain 2>/dev/null && chmod +x /usr/local/bin/findomain',
                'category': 'Subdomains',
                'description': 'Subdomain enumeration'
            },
            'sublist3r': {
                'apt': 'sublist3r',
                'pip': 'sublist3r',
                'brew': None,
                'category': 'Subdomains',
                'description': 'Subdomain enumeration'
            },
            'theharvester': {
                'apt': 'theharvester',
                'pip': 'theharvester',
                'brew': 'theharvester',
                'category': 'Subdomains',
                'description': 'Email and metadata harvester'
            },
            'nuclei': {
                'apt': 'nuclei',
                'pip': None,
                'brew': 'nuclei',
                'category': 'Vulnerabilities',
                'description': 'Fast vulnerability scanner with templates'
            },
        }
    
    def check_tool_installed(self, tool_name):
        """Check if a tool is installed - checks standard PATH, Go bins, and pipx paths"""
        try:
            binary = self.tool_aliases.get(tool_name, tool_name)
            # Special case: testssl may be installed as testssl.sh
            if tool_name == 'testssl':
                # Try both testssl and testssl.sh
                for cmd in ['testssl', 'testssl.sh']:
                    result = subprocess.run(
                        ['which', cmd] if self.os_type == "Linux" else ['where', cmd],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        return True
                return False
            
            # First try standard which/where
            result = subprocess.run(
                ['which', binary] if self.os_type == "Linux" else ['where', binary],
                capture_output=True
            )
            if result.returncode == 0:
                return True
            
            # Check Go bin directory for Go-installed tools (assetfinder, dalfox)
            if self.os_type == "Linux":
                go_bin_paths = [
                    os.path.expanduser('~/go/bin'),
                    os.path.expanduser('/root/go/bin'),
                    '/usr/local/go/bin'
                ]
                for go_bin in go_bin_paths:
                    tool_path = os.path.join(go_bin, binary)
                    if os.path.isfile(tool_path) and os.access(tool_path, os.X_OK):
                        return True
                
                # Check pipx installed tools path (sslyze, etc)
                pipx_paths = [
                    os.path.expanduser('~/.local/bin'),
                    os.path.expanduser('/root/.local/bin'),
                ]
                for pipx_bin in pipx_paths:
                    tool_path = os.path.join(pipx_bin, binary)
                    if os.path.isfile(tool_path) and os.access(tool_path, os.X_OK):
                        return True
            
            return False
        except:
            # Alternative check for Python packages
            try:
                pkg = self.tool_aliases.get(tool_name, tool_name)
                __import__(pkg)
                return True
            except ImportError:
                return False
    
    def scan_all_tools(self):
        """Scan for all tools in the database"""
        print("\n[*] Scanning for installed tools...")
        installed_count = 0
        missing_count = 0
        
        for tool, info in self.tool_database.items():
            if self.check_tool_installed(tool):
                self.installed_tools[tool] = info
                installed_count += 1
                print(f"✓ {tool:<20} ({info['category']:<15}) - INSTALLED")
            else:
                self.missing_tools[tool] = info
                missing_count += 1
                if tool not in self._warned:
                    print(f"✗ {tool:<20} ({info['category']:<15}) - MISSING")
                    self._warned.add(tool)
        
        print(f"\n[*] Summary: {installed_count} installed, {missing_count} missing")
        return installed_count, missing_count
    
    def get_install_command(self, tool_name):
        """Get installation command for a tool"""
        canonical = self.tool_aliases.get(tool_name, tool_name)
        tool_info = self.tool_database.get(canonical) or self.tool_database.get(tool_name)
        # If still not found, try reverse alias lookup (e.g., testssl.sh -> testssl)
        if not tool_info:
            for k, v in self.tool_aliases.items():
                if v == tool_name:
                    tool_info = self.tool_database.get(k)
                    if tool_info:
                        break
        if not tool_info:
            return None
        
        # Debian/Ubuntu/Kali/generic Linux systems
        if self.distro in ['ubuntu', 'debian', 'kali', 'linux']:
            # Check for custom installation command first (handles complex cases like Go + export PATH)
            if tool_info.get('custom'):
                return tool_info['custom']
            if tool_info.get('apt'):
                return f"apt-get install -y {tool_info['apt']}"
            elif tool_info.get('pip'):
                # Try pip3 with --break-system-packages first (PEP 668), then fallback
                return (
                    f"pip3 install {tool_info['pip']} --break-system-packages 2>/dev/null || "
                    f"pip3 install {tool_info['pip']} 2>/dev/null || "
                    f"pip install {tool_info['pip']}"
                )
            elif tool_info.get('go'):
                return f"go install {tool_info['go']}"
        
        # macOS
        elif self.distro == 'macos':
            if tool_info.get('brew'):
                return f"brew install {tool_info['brew']}"
            elif tool_info.get('pip'):
                return f"pip3 install {tool_info['pip']}"
        
        # Fallback for any other Linux-like systems: try apt, pip, then go
        else:
            if tool_info.get('custom'):
                return tool_info['custom']
            if tool_info.get('apt'):
                return f"apt-get install -y {tool_info['apt']}"
            elif tool_info.get('pip'):
                return (
                    f"pip3 install {tool_info['pip']} --break-system-packages 2>/dev/null || "
                    f"pip3 install {tool_info['pip']}"
                )
            elif tool_info.get('go'):
                return f"go install {tool_info['go']}"
        
        return None
    
    def install_tool(self, tool_name):
        """Install a single tool"""
        command = self.get_install_command(tool_name)
        if not command:
            print(f"[!] No installation method available for {tool_name}")
            return False
        
        print(f"[*] Installing {tool_name}...")
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] {tool_name} installed successfully")
                self.installed_tools[tool_name] = self.tool_database[tool_name]
                if tool_name in self.missing_tools:
                    del self.missing_tools[tool_name]
                return True
            else:
                if tool_name not in self._warned:
                    print(f"[-] Failed to install {tool_name}")
                    self._warned.add(tool_name)
                return False
        except Exception as e:
            print(f"[-] Error installing {tool_name}: {str(e)}")
            return False

    def install_missing_tools_non_interactive(self, preferred_tools: list[str] | None = None) -> tuple[int, int]:
        """Install all missing tools without prompts.

        If preferred_tools is provided, limit installation to that set (after aliasing).
        Returns (success_count, failed_count).
        """
        success = 0
        failed = 0
        if preferred_tools:
            # Build a set of canonical tool names to install
            targets = set()
            for t in preferred_tools:
                targets.add(self.tool_aliases.get(t, t))
        else:
            targets = set(self.tool_database.keys())

        for tool in sorted(targets):
            try:
                if self.check_tool_installed(tool):
                    continue
                cmd = self.get_install_command(tool)
                if not cmd:
                    if tool not in self._warned:
                        print(f"[!] No installer for {tool}")
                        self._warned.add(tool)
                    failed += 1
                    continue
                print(f"[*] Installing {tool}...")
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if res.returncode == 0:
                    print(f"[+] {tool} installed")
                    success += 1
                else:
                    print(f"[-] Failed to install {tool}: {res.stderr.strip() or res.stdout.strip()}")
                    failed += 1
            except Exception as e:
                print(f"[-] Error installing {tool}: {e}")
                failed += 1
        return success, failed
    
    def install_missing_tools_interactive(self):
        """Prompt user to install missing tools"""
        if not self.missing_tools:
            print("\n[+] All tools are installed!")
            return
        
        print(f"\n[!] {len(self.missing_tools)} tools are missing:")
        for i, (tool, info) in enumerate(self.missing_tools.items(), 1):
            print(f"{i}. {tool:<20} - {info['description']}")
        
        print("\nOptions:")
        print("1. Install all missing tools")
        print("2. Install specific tools")
        print("3. Skip installation")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == "1":
            print("\n[*] Installing all missing tools...")
            success = 0
            failed = 0
            # Iterate over a snapshot to avoid dict size change during iteration
            for tool in list(self.missing_tools.keys()):
                if self.install_tool(tool):
                    success += 1
                else:
                    failed += 1
            print(f"\n[*] Installation complete: {success} successful, {failed} failed")
        
        elif choice == "2":
            tool_list = list(self.missing_tools.keys())
            print("\nSelect tools to install:")
            for i, tool in enumerate(tool_list, 1):
                print(f"{i}. {tool}")
            
            selection = input("\nEnter numbers (comma-separated): ").strip()
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(",")]
                for idx in indices:
                    if 0 <= idx < len(tool_list):
                        self.install_tool(tool_list[idx])
            except ValueError:
                print("[-] Invalid input")
        
        elif choice == "3":
            print("[*] Skipping installation")
    
    def get_installed_tools_by_category(self):
        """Group installed tools by category"""
        categories = {}
        for tool, info in self.installed_tools.items():
            category = info['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(tool)
        return categories

    def register_custom_tool(self, tool_name: str, command: str, category: str = "custom", 
                           install_cmd: str = None, description: str = None) -> bool:
        """Register a new custom tool in the database for future use.
        
        Args:
            tool_name: Unique identifier for the tool
            command: Command to execute the tool
            category: Category for organization (default: custom)
            install_cmd: Optional installation command
            description: Optional description of what the tool does
            
        Returns:
            True if successfully registered, False otherwise
        """
        try:
            if not tool_name or not command:
                return False
            
            tool_entry = {
                "command": command,
                "category": category,
                "description": description or f"Custom tool: {tool_name}",
                "version": "custom",
            }
            
            if install_cmd:
                tool_entry["install"] = {
                    self.distro: install_cmd
                }
            
            # Update tool database
            if "custom_tools" not in self.tool_database:
                self.tool_database["custom_tools"] = {}
            
            self.tool_database["custom_tools"][tool_name] = tool_entry
            return True
        except Exception:
            return False

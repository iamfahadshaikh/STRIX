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
                'apt': None,
                'pip': 'sslyze',
                'brew': None,
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
                'pip': 'dalfox',
                'go': 'github.com/hahwul/dalfox/v2@latest',
                'brew': None,
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
            
            # Subdomain Tools
            'findomain': {
                'apt': None,  # Install from GitHub releases
                'pip': None,
                'go': None,  # Rust binary, use GitHub release
                'brew': 'findomain',
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
        }
    
    def check_tool_installed(self, tool_name):
        """Check if a tool is installed"""
        try:
            result = subprocess.run(
                ['which', tool_name] if self.os_type == "Linux" else ['where', tool_name],
                capture_output=True
            )
            return result.returncode == 0
        except:
            # Alternative check for Python packages
            try:
                __import__(tool_name)
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
        if tool_name not in self.tool_database:
            return None
        
        tool_info = self.tool_database[tool_name]
        
        if self.distro in ['ubuntu', 'debian', 'kali']:
            if tool_info.get('apt'):
                return f"sudo apt-get install -y {tool_info['apt']}"
            elif tool_info.get('pip'):
                    # Prefer --break-system-packages on Kali/PEP668-managed envs
                    # to avoid installation blocking. Falls back to standard pip3.
                    # We also try pipx if available for CLI tools.
                    return (
                        f"pip3 install {tool_info['pip']} --break-system-packages || "
                        f"pip3 install {tool_info['pip']}"
                    )
            elif tool_info.get('go'):
                return f"go install {tool_info['go']}"
        
        elif self.distro == 'macos':
            if tool_info.get('brew'):
                return f"brew install {tool_info['brew']}"
            elif tool_info.get('pip'):
                return f"pip3 install {tool_info['pip']}"
        
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

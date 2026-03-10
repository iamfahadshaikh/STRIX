#!/usr/bin/env python3
"""
Interactive Tool Checker and Installer
Lists all tools, detects what's installed, and prompts for installation
"""

import subprocess
import sys
import platform
from pathlib import Path
from tool_manager import ToolManager


class InteractiveToolChecker:
    def __init__(self):
        self.tool_manager = ToolManager()
        self.selected_tools = []
        
    def display_header(self):
        """Display header"""
        print("\n" + "="*80)
        print("SECURITY SCANNER - INTERACTIVE TOOL INSTALLER")
        print("="*80)
        print(f"Operating System: {self.tool_manager.os_type}")
        print(f"Distribution: {self.tool_manager.distro}")
        print("="*80 + "\n")
    
    def check_and_prompt(self):
        """Check all tools and prompt user for installation"""
        print("[*] Scanning for installed tools...\n")
        
        # Group tools by category
        tools_by_category = {}
        for tool, info in self.tool_manager.tool_database.items():
            category = info.get('category', 'Other')
            if category not in tools_by_category:
                tools_by_category[category] = []
            tools_by_category[category].append((tool, info))
        
        installed_count = 0
        missing_count = 0
        total_count = len(self.tool_manager.tool_database)
        
        # Display tools by category
        for category in sorted(tools_by_category.keys()):
            print(f"\n{'─'*80}")
            print(f"📁 {category}")
            print(f"{'─'*80}")
            
            for tool, info in sorted(tools_by_category[category]):
                is_installed = self.tool_manager.check_tool_installed(tool)
                description = info.get('description', 'No description')
                
                if is_installed:
                    status_icon = "✅"
                    status_text = "INSTALLED"
                    installed_count += 1
                else:
                    status_icon = "❌"
                    status_text = "MISSING"
                    missing_count += 1
                
                print(f"  {status_icon} {tool:<20} - {description:<40} [{status_text}]")
        
        # Summary
        print(f"\n{'='*80}")
        print(f"SUMMARY: {installed_count}/{total_count} tools installed, {missing_count} missing")
        print(f"{'='*80}\n")
        
        return missing_count > 0
    
    def prompt_for_installation(self):
        """Prompt user for each missing tool"""
        print("\n[*] Checking which tools to install...\n")
        
        # Group missing tools by category
        missing_by_category = {}
        for tool, info in self.tool_manager.tool_database.items():
            if not self.tool_manager.check_tool_installed(tool):
                category = info.get('category', 'Other')
                if category not in missing_by_category:
                    missing_by_category[category] = []
                missing_by_category[category].append((tool, info))
        
        if not missing_by_category:
            print("✅ All tools are already installed!")
            return
        
        print(f"Found {sum(len(v) for v in missing_by_category.values())} missing tools.\n")
        
        # Prompt for each missing tool
        for category in sorted(missing_by_category.keys()):
            print(f"\n{'─'*80}")
            print(f"📁 {category}")
            print(f"{'─'*80}")
            
            for tool, info in sorted(missing_by_category[category]):
                description = info.get('description', 'No description')
                command = self.tool_manager.get_install_command(tool)
                
                if not command:
                    print(f"\n❌ {tool}")
                    print(f"   Description: {description}")
                    print(f"   ⚠️  NO INSTALLATION METHOD AVAILABLE")
                    continue
                
                print(f"\n📦 {tool}")
                print(f"   Description: {description}")
                print(f"   Command: {command}")
                
                # Prompt user
                while True:
                    response = input(f"   Install {tool}? [y/n/a(ll)/s(kip all)]: ").strip().lower()
                    if response in ['y', 'n', 'a', 's']:
                        if response == 'y':
                            self.selected_tools.append(tool)
                        elif response == 'a':
                            # Add current tool and all remaining tools with install commands
                            print(f"\n[*] Installing all remaining tools...\n")
                            self.selected_tools.append(tool)
                            # Add all remaining tools from this category
                            for remaining_tool, remaining_info in sorted(missing_by_category[category]):
                                if remaining_tool != tool and self.tool_manager.get_install_command(remaining_tool):
                                    if remaining_tool not in self.selected_tools:
                                        self.selected_tools.append(remaining_tool)
                            # Add all tools from remaining categories
                            current_category_index = sorted(missing_by_category.keys()).index(category)
                            for next_category in sorted(missing_by_category.keys())[current_category_index + 1:]:
                                for next_tool, next_info in sorted(missing_by_category[next_category]):
                                    if self.tool_manager.get_install_command(next_tool):
                                        if next_tool not in self.selected_tools:
                                            self.selected_tools.append(next_tool)
                            return
                        elif response == 's':
                            print(f"\n[*] Skipping remaining tools...\n")
                            return
                        break
                    else:
                        print("   ⚠️  Please enter 'y', 'n', 'a', or 's'")
    
    def install_selected(self):
        """Install all selected tools"""
        if not self.selected_tools:
            print("\n[*] No tools selected for installation")
            return
        
        print(f"\n{'='*80}")
        print(f"INSTALLING {len(self.selected_tools)} SELECTED TOOLS")
        print(f"{'='*80}\n")
        
        success_count = 0
        failed_tools = []
        
        for i, tool in enumerate(self.selected_tools, 1):
            print(f"\n[{i}/{len(self.selected_tools)}] Installing {tool}...")
            print(f"{'─'*80}")
            
            # Get install command
            command = self.tool_manager.get_install_command(tool)
            if not command:
                print(f"❌ No installation method for {tool}")
                failed_tools.append(tool)
                continue
            
            # Try to install
            try:
                print(f"Command: {command}\n")
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=False,
                    text=True,
                    timeout=600
                )
                
                if result.returncode == 0:
                    # Verify installation
                    if self.tool_manager.check_tool_installed(tool):
                        print(f"\n✅ {tool} installed successfully!")
                        success_count += 1
                    else:
                        print(f"\n⚠️  {tool} installation command ran but tool not detected")
                        failed_tools.append(tool)
                else:
                    print(f"\n❌ {tool} installation failed (exit code: {result.returncode})")
                    failed_tools.append(tool)
            
            except subprocess.TimeoutExpired:
                print(f"\n❌ {tool} installation TIMEOUT (600s)")
                failed_tools.append(tool)
            
            except Exception as e:
                print(f"\n❌ {tool} installation ERROR: {e}")
                failed_tools.append(tool)
        
        # Final summary
        print(f"\n{'='*80}")
        print(f"INSTALLATION SUMMARY")
        print(f"{'='*80}")
        print(f"✅ Successfully installed: {success_count}")
        if failed_tools:
            print(f"❌ Failed: {len(failed_tools)}")
            for tool in failed_tools:
                print(f"   - {tool}")
        print(f"{'='*80}\n")
    
    def run(self):
        """Run the interactive checker"""
        self.display_header()
        
        # Check and display all tools
        has_missing = self.check_and_prompt()
        
        if has_missing:
            # Prompt for each missing tool
            try:
                self.prompt_for_installation()
            except KeyboardInterrupt:
                print("\n\n[*] Installation cancelled by user")
                return False
            
            # Install selected tools
            if self.selected_tools:
                self.install_selected()
                print("\n✅ Installation phase complete!")
            else:
                print("\n[*] No tools selected for installation")
        else:
            print("✅ All tools are already installed!")
        
        print("\n[*] Ready to run security scanner\n")
        return True


if __name__ == '__main__':
    checker = InteractiveToolChecker()
    success = checker.run()
    sys.exit(0 if success else 1)

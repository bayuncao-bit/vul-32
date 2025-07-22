# MCPAdapt Command Injection Vulnerability Report

## Summary

A critical Remote Code Execution (RCE) vulnerability exists in the MCPAdapt library's handling of `StdioServerParameters`. The vulnerability allows arbitrary command execution through insufficient input validation when establishing connections to MCP servers. User-controlled input is directly passed to the underlying MCP Python SDK's `stdio_client()` function without sanitization, enabling attackers to execute arbitrary system commands with the privileges of the MCPAdapt client process.

---

## Description

The MCPAdapt library provides adapters to integrate MCP (Model Context Protocol) servers with various agentic frameworks. The vulnerability stems from the direct use of user-controlled `StdioServerParameters` in the `mcptools()` function and `MCPAdapt` class without proper validation.

When a `StdioServerParameters` object is passed to MCPAdapt, it is directly forwarded to the MCP Python SDK's `stdio_client()` function, which eventually calls `anyio.open_process()` with the user-provided command and arguments. This creates a direct path for command injection attacks.

The vulnerability affects both synchronous and asynchronous usage patterns of MCPAdapt, as both code paths ultimately use the same vulnerable `mcptools()` function.

---

## Affected Code

### Primary Vulnerability Sink

**File**: `src/mcpadapt/core.py`
**Function**: `mcptools()`
**Lines**: 60-85

The vulnerable code directly passes user input to `stdio_client()`:

```python
@asynccontextmanager
async def mcptools(
    serverparams: StdioServerParameters | dict[str, Any],
    client_session_timeout_seconds: float | timedelta | None = 5,
) -> AsyncGenerator[tuple[ClientSession, list[mcp.types.Tool]], None]:
    if isinstance(serverparams, StdioServerParameters):
        client = stdio_client(serverparams)  # ← Vulnerable: No validation
```

### Secondary Vulnerability Points

**File**: `src/mcpadapt/core.py`
**Class**: `MCPAdapt`
**Methods**: `__init__()`, `_run_loop()`, `__aenter__()`

The `MCPAdapt` class constructor accepts `StdioServerParameters` and passes them directly to the vulnerable `mcptools()` function:

```python
def __init__(
    self,
    serverparams: StdioServerParameters | dict[str, Any] | list[StdioServerParameters | dict[str, Any]],
    adapter: ToolAdapter,
    # ...
):
    if isinstance(serverparams, list):
        self.serverparams = serverparams
    else:
        self.serverparams = [serverparams]  # ← User input stored without validation
```

---

## Proof of Concept

The vulnerability can be exploited through any code that uses MCPAdapt with user-controlled `StdioServerParameters`. Here's a minimal PoC:

```python
from mcp import StdioServerParameters
from mcpadapt.core import MCPAdapt, ToolAdapter

class DummyAdapter(ToolAdapter):
    def adapt(self, func, mcp_tool):
        return func

# Command injection via malicious server parameters
malicious_params = StdioServerParameters(
    command="touch",
    args=["/tmp/command_injection_proof.txt"]
)

# This will execute: touch /tmp/command_injection_proof.txt
with MCPAdapt(malicious_params, DummyAdapter()) as tools:
    pass  # Command executes during context manager initialization
```

The attack vector is particularly dangerous because:

1. **No validation**: MCPAdapt accepts any command and arguments
2. **Direct execution**: Commands are executed immediately during initialization
3. **Privilege escalation**: Commands run with the same privileges as the MCPAdapt process
4. **Framework integration**: The vulnerability affects all supported agentic frameworks

---

## Impact

This vulnerability has severe security implications:

### Immediate Risks
- **Remote Code Execution**: Attackers can execute arbitrary system commands
- **Data Exfiltration**: Access to sensitive files and environment variables
- **System Compromise**: Full control over the host system with process privileges
- **Lateral Movement**: Potential to compromise connected systems and networks

### Attack Scenarios
1. **AI Assistant Exploitation**: Users can inject commands through natural language prompts that generate malicious `StdioServerParameters`
2. **Configuration-based Attacks**: Malicious MCP server configurations in applications
3. **Supply Chain Attacks**: Compromised MCP servers or configurations distributed through package managers
4. **Automated Exploitation**: Programmatic exploitation through any application using MCPAdapt

### Affected Frameworks
All supported agentic frameworks are vulnerable:
- Smolagents
- LangChain  
- CrewAI
- Google GenAI
- LlamaIndex

---

## Occurrences

- [src/mcpadapt/core.py:67](https://github.com/grll/mcpadapt/blob/main/src/mcpadapt/core.py#L67) - Primary vulnerability in `mcptools()` function
- [src/mcpadapt/core.py:156](https://github.com/grll/mcpadapt/blob/main/src/mcpadapt/core.py#L156) - Vulnerable parameter storage in `MCPAdapt.__init__()`
- [src/mcpadapt/core.py:175](https://github.com/grll/mcpadapt/blob/main/src/mcpadapt/core.py#L175) - Vulnerable usage in `_run_loop()` method
- [src/mcpadapt/core.py:295](https://github.com/grll/mcpadapt/blob/main/src/mcpadapt/core.py#L295) - Vulnerable usage in async context manager `__aenter__()`
- [examples/smolagents_pubmed.py:18](https://github.com/grll/mcpadapt/blob/main/examples/smolagents_pubmed.py#L18) - Example demonstrating vulnerable usage pattern
- [examples/langchain_pubmed.py:18](https://github.com/grll/mcpadapt/blob/main/examples/langchain_pubmed.py#L18) - Example demonstrating vulnerable usage pattern

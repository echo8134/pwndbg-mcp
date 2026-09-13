"""GDB core tools: session, execution, breakpoints, data, stack, threads."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeAlias

from mcp.server.fastmcp import FastMCP

from .gdb_controller import AsyncGdbController
from .utils import format_error, format_responses

ControllerGetter: TypeAlias = Callable[[], Awaitable[AsyncGdbController]]


def register_gdb_tools(mcp: FastMCP, get_controller: ControllerGetter) -> None:
    """Register all GDB core tools on the FastMCP instance."""

    # ===================================================================
    # Session Management
    # ===================================================================

    @mcp.tool()
    async def load_binary(path: str, args: str = "") -> str:
        """Load an ELF binary into GDB for debugging.

        Args:
            path: Path to the binary to debug.
            args: Optional command-line arguments for the program.
        """
        try:
            if any(char in path for char in "\r\n\0"):
                raise ValueError("Binary path must not contain NUL or newline characters.")
            # MI strings escape quotes and backslashes. Keep other filename characters literal.
            quoted_path = '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'
            gdb = await get_controller()
            responses = await gdb.execute(f"-file-exec-and-symbols {quoted_path}")
            if args:
                responses += await gdb.execute_console(f"set args {args}")
            return format_responses(responses) or f"Loaded {path}"
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def attach_process(pid: int) -> str:
        """Attach GDB to a running process by PID.

        Args:
            pid: Process ID to attach to.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-target-attach {pid}")
            return format_responses(responses) or f"Attached to PID {pid}"
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def detach_process() -> str:
        """Detach GDB from the current process."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute("-target-detach")
            return format_responses(responses) or "Detached."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def remote_connect(host: str, port: int) -> str:
        """Connect to a remote GDB server (gdbserver).

        Args:
            host: Hostname or IP address.
            port: Port number.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-target-select remote {host}:{port}")
            return format_responses(responses) or f"Connected to {host}:{port}"
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def remote_disconnect() -> str:
        """Disconnect from a remote GDB target."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute("-target-disconnect")
            return format_responses(responses) or "Disconnected."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Execution Control
    # ===================================================================

    @mcp.tool()
    async def run_program(args: str = "", stop_at_main: bool = False) -> str:
        """Start running the loaded program from the beginning.

        Args:
            args: Optional command-line arguments (overrides set args).
            stop_at_main: If true, stop at main() instead of running freely.
        """
        try:
            gdb = await get_controller()
            if args:
                await gdb.execute_console(f"set args {args}")
            cmd = "-exec-run --start" if stop_at_main else "-exec-run"
            responses = await gdb.execute(cmd)
            if stop_at_main:
                # Drain to catch the *stopped notification when main() is hit
                drain = await gdb.drain_responses(timeout_sec=5.0)
                responses.extend(drain)
            return format_responses(responses) or "Program started."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def continue_execution(reverse: bool = False) -> str:
        """Continue program execution until next breakpoint or exit.

        Args:
            reverse: If true, continue in reverse (requires record mode).
        """
        try:
            gdb = await get_controller()
            cmd = "-exec-continue --reverse" if reverse else "-exec-continue"
            responses = await gdb.execute(cmd)
            return format_responses(responses) or "Continuing."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def step_into(count: int = 1) -> str:
        """Step into the next source line (enters function calls).

        Args:
            count: Number of lines to step.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-exec-step {count}")
            return format_responses(responses) or "Stepped."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def step_over(count: int = 1) -> str:
        """Step over the next source line (skips into function calls).

        Args:
            count: Number of lines to step over.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-exec-next {count}")
            return format_responses(responses) or "Stepped over."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def step_instruction(count: int = 1) -> str:
        """Step one machine instruction (enters calls).

        Args:
            count: Number of instructions to step.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-exec-step-instruction {count}")
            return format_responses(responses) or "Stepped instruction."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def next_instruction(count: int = 1) -> str:
        """Step one machine instruction (skips calls).

        Args:
            count: Number of instructions to step over.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-exec-next-instruction {count}")
            return format_responses(responses) or "Next instruction."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def finish_function() -> str:
        """Execute until the current function returns."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute("-exec-finish")
            return format_responses(responses) or "Function finished."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def interrupt_execution() -> str:
        """Interrupt a running program (like Ctrl-C in GDB)."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute("-exec-interrupt")
            # Drain to catch the *stopped notification confirming the interrupt
            drain = await gdb.drain_responses(timeout_sec=3.0)
            responses.extend(drain)
            return format_responses(responses) or "Interrupted."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def kill_program() -> str:
        """Kill the running program."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("kill")
            return format_responses(responses) or "Program killed."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Breakpoints
    # ===================================================================

    async def _check_insn_boundary(
        gdb: AsyncGdbController, location: str
    ) -> str:
        """Check if a raw *0x... address lands on an instruction boundary.

        Uses -data-disassemble to get instruction starts in a small window
        around the target address. If the address doesn't match any
        instruction start, returns a warning string. Otherwise returns "".

        Note: x86-64 has variable-length instructions (up to 15 bytes).
        If the start of the disassembly window falls mid-instruction,
        GDB's linear-sweep disassembler may re-sync incorrectly, which
        could produce a false negative. This is a best-effort heuristic.
        """
        try:
            addr_str = location.removeprefix("*")
            addr = int(addr_str, 16)
            # Disassemble a window around the target: 32 bytes before to
            # 16 bytes after. The larger backward window reduces the chance
            # of starting mid-instruction on variable-length ISAs.
            start = max(0, addr - 32)
            end = addr + 16
            responses = await gdb.execute(
                f"-data-disassemble -s {start:#x} -e {end:#x} -- 0"
            )
            # Parse instruction addresses from the structured response.
            insn_addrs: set[int] = set()
            for resp in responses:
                payload = resp.get("payload")
                if not isinstance(payload, dict):
                    continue
                asm_insns = payload.get("asm_insns", [])
                for insn in asm_insns:
                    insn_addr = insn.get("address")
                    if insn_addr is not None:
                        insn_addrs.add(int(insn_addr, 0))
            if insn_addrs and addr not in insn_addrs:
                # Find the instruction that contains this address
                before = sorted(a for a in insn_addrs if a <= addr)
                containing = hex(before[-1]) if before else "unknown"
                return (
                    f"Address {addr:#x} is NOT at an instruction boundary. "
                    f"It falls inside the instruction at {containing}. "
                    f"Setting a breakpoint here will corrupt that instruction's "
                    f"encoding (INT3 overwrites a mid-instruction byte). "
                    f"Nearby valid addresses: "
                    f"{', '.join(hex(a) for a in sorted(insn_addrs) if abs(a - addr) <= 16)}"
                )
        except Exception:
            # If disassembly fails (no binary loaded, unmapped address),
            # skip validation silently and let GDB handle it.
            pass
        return ""

    @mcp.tool()
    async def set_breakpoint(
        location: str,
        condition: str = "",
        temporary: bool = False,
        hardware: bool = False,
    ) -> str:
        """Set a breakpoint at the specified location.

        Args:
            location: Where to break — function name, file:line, or *address.
            condition: Optional condition expression (break only when true).
            temporary: If true, breakpoint auto-deletes after first hit.
            hardware: If true, use a hardware breakpoint.
        """
        try:
            gdb = await get_controller()

            # Validate raw-address software breakpoints land on instruction
            # boundaries. A breakpoint in the middle of a multi-byte
            # instruction (e.g. inside a call's displacement) corrupts that
            # instruction when GDB writes the INT3 byte, causing silent
            # misbehavior or crashes. Hardware breakpoints use debug
            # registers and don't modify instructions, so skip the check.
            warning = ""
            if not hardware and (
                location.startswith("*0x") or location.startswith("*0X")
            ):
                warning = await _check_insn_boundary(gdb, location)

            parts = ["-break-insert"]
            if temporary:
                parts.append("-t")
            if hardware:
                parts.append("-h")
            if condition:
                parts.extend(["-c", f'"{condition}"'])
            parts.append(location)
            responses = await gdb.execute(" ".join(parts))
            result = format_responses(responses) or f"Breakpoint set at {location}"
            if warning:
                result = f"WARNING: {warning}\n{result}"
            return result
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def delete_breakpoint(number: int) -> str:
        """Delete a breakpoint by its number.

        Args:
            number: Breakpoint number (from list_breakpoints).
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-break-delete {number}")
            return format_responses(responses) or f"Breakpoint {number} deleted."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def enable_breakpoint(number: int) -> str:
        """Enable a disabled breakpoint.

        Args:
            number: Breakpoint number.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-break-enable {number}")
            return format_responses(responses) or f"Breakpoint {number} enabled."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def disable_breakpoint(number: int) -> str:
        """Disable a breakpoint without deleting it.

        Args:
            number: Breakpoint number.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-break-disable {number}")
            return format_responses(responses) or f"Breakpoint {number} disabled."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def list_breakpoints() -> str:
        """List all breakpoints, watchpoints, and catchpoints."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute("-break-list")
            return format_responses(responses) or "No breakpoints."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def set_watchpoint(expression: str, access_type: str = "write") -> str:
        """Set a watchpoint on a memory expression.

        Args:
            expression: Expression to watch (variable name or *address).
            access_type: 'write' (default), 'read', or 'access' (read/write).
        """
        try:
            gdb = await get_controller()
            flag = ""
            if access_type == "read":
                flag = "-r"
            elif access_type == "access":
                flag = "-a"
            cmd = f"-break-watch {flag} {expression}".strip()
            responses = await gdb.execute(cmd)
            return format_responses(responses) or f"Watchpoint set on {expression}"
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Data Inspection
    # ===================================================================

    @mcp.tool()
    async def read_registers(registers: str = "") -> str:
        """Read CPU register values.

        Args:
            registers: Space-separated register names (e.g. 'rax rbx rsp').
                       Empty string reads all registers.
        """
        try:
            gdb = await get_controller()
            if registers:
                # Use info registers for named register query
                responses = await gdb.execute_console(f"info registers {registers}")
            else:
                responses = await gdb.execute("-data-list-register-values x")
            return format_responses(responses) or "No register data."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def write_register(register: str, value: str) -> str:
        """Write a value to a CPU register.

        Args:
            register: Register name (e.g. 'rax', 'rip').
            value: Value to set (hex like 0xdeadbeef or decimal).
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"set ${register} = {value}")
            return format_responses(responses) or f"${register} = {value}"
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def read_memory(address: str, count: int = 64, format: str = "x") -> str:
        """Read raw memory bytes at an address.

        Args:
            address: Memory address (hex like 0x400000 or expression).
            count: Number of bytes to read (default 64).
            format: Display format — 'x' hex (default), or use hexdump.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-data-read-memory-bytes {address} {count}")
            return format_responses(responses) or "No data."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def write_memory(address: str, data: str) -> str:
        """Write bytes to memory at an address.

        Args:
            address: Memory address (hex like 0x400000).
            data: Hex string of bytes to write (e.g. '41424344' for 'ABCD').
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-data-write-memory-bytes {address} {data}")
            return format_responses(responses) or f"Wrote to {address}"
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def disassemble(start: str, end: str = "", count: int = 0) -> str:
        """Disassemble instructions at an address or range.

        Args:
            start: Start address or function name.
            end: Optional end address.
            count: Optional number of instructions (alternative to end).
        """
        try:
            gdb = await get_controller()
            if count > 0:
                # Use console disassemble for instruction count
                responses = await gdb.execute_console(f"x/{count}i {start}")
            elif end:
                responses = await gdb.execute(f"-data-disassemble -s {start} -e {end} -- 0")
            else:
                responses = await gdb.execute(f"-data-disassemble -s {start} -e {start}+100 -- 0")
            return format_responses(responses) or "No instructions."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def evaluate_expression(expression: str) -> str:
        """Evaluate an expression in the current context.

        Args:
            expression: C expression, variable name, register ($rax), or GDB convenience var.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-data-evaluate-expression {expression}")
            return format_responses(responses) or "No result."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Stack
    # ===================================================================

    @mcp.tool()
    async def backtrace(count: int = 0) -> str:
        """Show the call stack (backtrace).

        Args:
            count: Max number of frames to show (0 = all).
        """
        try:
            gdb = await get_controller()
            if count > 0:
                responses = await gdb.execute(f"-stack-list-frames 0 {count - 1}")
            else:
                responses = await gdb.execute("-stack-list-frames")
            return format_responses(responses) or "No stack frames."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def stack_locals() -> str:
        """Show local variables in the current stack frame."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute("-stack-list-locals 1")
            return format_responses(responses) or "No locals."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def stack_args() -> str:
        """Show function arguments in the current stack frame."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("info args")
            return format_responses(responses) or "No arguments."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def select_frame(number: int) -> str:
        """Select a stack frame by number.

        Args:
            number: Frame number (0 = innermost/current).
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-stack-select-frame {number}")
            return format_responses(responses) or f"Selected frame {number}."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Threads
    # ===================================================================

    @mcp.tool()
    async def list_threads() -> str:
        """List all threads in the debugged process."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute("-thread-info")
            return format_responses(responses) or "No threads."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def switch_thread(thread_id: int) -> str:
        """Switch to a different thread.

        Args:
            thread_id: Thread ID to switch to.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute(f"-thread-select {thread_id}")
            return format_responses(responses) or f"Switched to thread {thread_id}."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Escape Hatch
    # ===================================================================

    @mcp.tool()
    async def execute_command(command: str, timeout: int = 10) -> str:
        """Execute any raw GDB/MI or console command.

        Use this for any GDB functionality not covered by other tools.
        Prefix with '-' for MI commands, otherwise runs as console command.

        Args:
            command: The GDB command to execute.
            timeout: Timeout in seconds (default 10).
        """
        try:
            gdb = await get_controller()
            if command.startswith("-"):
                responses = await gdb.execute(command, timeout_sec=timeout)
            else:
                responses = await gdb.execute_console(command, timeout_sec=timeout)
            return format_responses(responses) or "(no output)"
        except Exception as e:
            return format_error(e)

"""pwndbg extension tools: context, memory, heap, binary info, exploit helpers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeAlias

from mcp.server.fastmcp import FastMCP

from .gdb_controller import AsyncGdbController
from .utils import format_console_output, format_error

ControllerGetter: TypeAlias = Callable[[], Awaitable[AsyncGdbController]]


def register_pwndbg_tools(mcp: FastMCP, get_controller: ControllerGetter) -> None:
    """Register pwndbg extension tools on the FastMCP instance."""

    # ===================================================================
    # Memory inspection
    # ===================================================================

    @mcp.tool()
    async def pwndbg_context(subsection: str = "") -> str:
        """Show pwndbg context display: registers, disassembly, stack, backtrace.

        Args:
            subsection: Optional subsection to show (e.g. 'regs', 'disasm', 'stack', 'backtrace').
                        Empty shows the full context.
        """
        try:
            gdb = await get_controller()
            cmd = f"context {subsection}" if subsection else "context"
            responses = await gdb.execute_console(cmd)
            return format_console_output(responses) or "No context output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def telescope(address: str = "", count: int = 10) -> str:
        """Dereference pointers recursively starting from an address.

        Args:
            address: Start address (hex or expression). Empty defaults to $sp.
            count: Number of entries to display.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"telescope {address or '$sp'} {count}")
            return format_console_output(responses) or "No telescope output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def vmmap(pattern: str = "") -> str:
        """Show virtual memory map of the process.

        Args:
            pattern: Optional filter pattern (e.g. 'libc', 'heap', 'stack').
        """
        try:
            gdb = await get_controller()
            cmd = f"vmmap {pattern}" if pattern else "vmmap"
            responses = await gdb.execute_console(cmd)
            return format_console_output(responses) or "No vmmap output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def hexdump_memory(address: str = "", count: int = 64) -> str:
        """Hex dump memory at an address.

        Args:
            address: Memory address (hex or expression). Empty defaults to $sp.
            count: Number of bytes to dump.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"hexdump {address or '$sp'} {count}")
            return format_console_output(responses) or "No hexdump output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def xinfo(address: str) -> str:
        """Show information about what a memory address belongs to (mapping, section, symbol).

        Args:
            address: Memory address to inspect.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"xinfo {address}")
            return format_console_output(responses) or "No xinfo output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def search_memory(value: str, type: str = "") -> str:
        """Search process memory for a value.

        Args:
            value: Value to search for (string, hex bytes, integer).
            type: Optional type hint: 'byte', 'short', 'dword', 'qword', 'string', 'bytes'.
        """
        try:
            gdb = await get_controller()
            if type:
                cmd = f"search -t {type} {value}"
            else:
                cmd = f"search {value}"
            responses = await gdb.execute_console(cmd)
            return format_console_output(responses) or "No search results."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def probeleak(address: str = "", count: int = 0) -> str:
        """Probe memory for pointers to known regions (heap, stack, libc, etc.).

        Args:
            address: Start address to probe. Empty defaults to $sp.
            count: Number of bytes to probe. Zero or less uses pwndbg's default.
        """
        try:
            gdb = await get_controller()
            parts = ["probeleak", address or "$sp"]
            if count > 0:
                parts.append(str(count))
            responses = await gdb.execute_console(" ".join(parts))
            return format_console_output(responses) or "No probeleak output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def leakfind(address: str = "") -> str:
        """Find chains of pointers starting from an address to known regions.

        Args:
            address: Start address to search from. Empty defaults to current context.
        """
        try:
            gdb = await get_controller()
            cmd = f"leakfind {address}" if address else "leakfind"
            responses = await gdb.execute_console(cmd)
            return format_console_output(responses) or "No leakfind output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def distance(addr1: str, addr2: str) -> str:
        """Calculate the distance between two addresses.

        Args:
            addr1: First address (hex or expression).
            addr2: Second address (hex or expression).
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"distance {addr1} {addr2}")
            return format_console_output(responses) or "No distance output."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Heap / glibc
    # ===================================================================

    @mcp.tool()
    async def heap_bins() -> str:
        """Show all free list bins (tcache, fast, unsorted, small, large)."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("bins")
            return format_console_output(responses) or "No bins output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def heap_overview() -> str:
        """Show an overview of the heap state."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("heap")
            return format_console_output(responses) or "No heap output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def vis_heap_chunks(address: str = "") -> str:
        """Visual representation of heap chunks with color-coded boundaries.

        Args:
            address: Optional heap address to start from. Empty shows the main arena.
        """
        try:
            gdb = await get_controller()
            cmd = f"vis-heap-chunks {address}" if address else "vis-heap-chunks"
            responses = await gdb.execute_console(cmd)
            return format_console_output(responses) or "No vis_heap_chunks output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def malloc_chunk(address: str) -> str:
        """Inspect a specific malloc chunk header and metadata.

        Args:
            address: Address of the malloc chunk to inspect.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"malloc-chunk {address}")
            return format_console_output(responses) or "No malloc_chunk output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def top_chunk() -> str:
        """Show the top (wilderness) chunk of the heap."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("top-chunk")
            return format_console_output(responses) or "No top_chunk output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def heap_arenas() -> str:
        """List all malloc arenas."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("arenas")
            return format_console_output(responses) or "No arenas output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def tcachebins() -> str:
        """Show tcache bin entries and their contents."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("tcachebins")
            return format_console_output(responses) or "No tcachebins output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def fastbins() -> str:
        """Show fast bin entries and their contents."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("fastbins")
            return format_console_output(responses) or "No fastbins output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def unsortedbin() -> str:
        """Show unsorted bin entries."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("unsortedbin")
            return format_console_output(responses) or "No unsortedbin output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def smallbins() -> str:
        """Show small bin entries and their contents."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("smallbins")
            return format_console_output(responses) or "No smallbins output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def largebins() -> str:
        """Show large bin entries and their contents."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("largebins")
            return format_console_output(responses) or "No largebins output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def find_fake_fast(address: str) -> str:
        """Find candidate locations for fake fastbin chunks near an address.

        Args:
            address: Target address to search near for fake chunk candidates.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"find-fake-fast {address}")
            return format_console_output(responses) or "No find_fake_fast output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def try_free(address: str) -> str:
        """Simulate what free() would do on a chunk, checking for errors.

        Args:
            address: Address of the chunk to simulate freeing.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"try-free {address}")
            return format_console_output(responses) or "No try_free output."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Binary information
    # ===================================================================

    @mcp.tool()
    async def checksec() -> str:
        """Show binary security features: NX, PIE, RELRO, stack canary, FORTIFY."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("checksec")
            return format_console_output(responses) or "No checksec output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def got_table() -> str:
        """Show Global Offset Table entries and their resolved addresses."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("got")
            return format_console_output(responses) or "No GOT output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def plt_table() -> str:
        """Show Procedure Linkage Table entries."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("plt")
            return format_console_output(responses) or "No PLT output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def piebase() -> str:
        """Show the PIE base address of the loaded binary."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("piebase")
            return format_console_output(responses) or "No piebase output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def elf_sections() -> str:
        """List all ELF sections of the loaded binary."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("elfsections")
            return format_console_output(responses) or "No elfsections output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def libcinfo() -> str:
        """Show libc version and path information."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("libcinfo")
            return format_console_output(responses) or "No libcinfo output."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Exploit helpers
    # ===================================================================

    @mcp.tool()
    async def rop_gadgets(regex: str = "") -> str:
        """Find ROP gadgets in the loaded binary.

        Args:
            regex: Optional regex to filter gadgets (e.g. 'pop rdi').
        """
        try:
            gdb = await get_controller()
            cmd = f"rop --grep {regex}" if regex else "rop"
            responses = await gdb.execute_console(cmd)
            return format_console_output(responses) or "No ROP gadgets found."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def cyclic_pattern(count: int = 200) -> str:
        """Generate a De Bruijn cyclic pattern for finding offsets.

        Args:
            count: Length of the pattern to generate.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"cyclic {count}")
            return format_console_output(responses) or "No cyclic output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def cyclic_find(value: str) -> str:
        """Find the offset of a value in the De Bruijn cyclic pattern.

        Args:
            value: Value to look up (hex or substring from the pattern).
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"cyclic -l {value}")
            return format_console_output(responses) or "No cyclic lookup result."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def onegadget() -> str:
        """Find one-gadget RCE candidates in libc."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("one_gadget")
            return format_console_output(responses) or "No one_gadget output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def canary() -> str:
        """Show the current stack canary value."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("canary")
            return format_console_output(responses) or "No canary output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def retaddr() -> str:
        """Show return addresses on the stack for the current frame."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("retaddr")
            return format_console_output(responses) or "No retaddr output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def sigreturn_frame(address: str = "") -> str:
        """Generate a sigreturn frame for SROP exploitation.

        Args:
            address: Optional address for the sigreturn frame.
        """
        try:
            gdb = await get_controller()
            cmd = f"sigreturn {address}" if address else "sigreturn"
            responses = await gdb.execute_console(cmd)
            return format_console_output(responses) or "No sigreturn output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def dumpargs() -> str:
        """Dump function arguments at the current position based on calling convention."""
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console("dumpargs")
            return format_console_output(responses) or "No dumpargs output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def patch_instruction(address: str, instruction: str) -> str:
        """Patch an instruction in memory at the given address.

        Args:
            address: Address of the instruction to patch.
            instruction: New assembly instruction (e.g. 'nop', 'ret', 'jmp 0x401000').
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f'patch {address} "{instruction}"')
            return format_console_output(responses) or f"Patched at {address}."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Execution and disassembly
    # ===================================================================

    @mcp.tool()
    async def nearpc(address: str = "", count: int = 10) -> str:
        """Show disassembly around an address with context.

        Args:
            address: Address or symbol to disassemble around. Empty defaults to $pc.
            count: Number of instruction lines from the address onward.
                   Pwndbg may also show preceding instructions.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"nearpc {address or '$pc'} {count}")
            return format_console_output(responses) or "No nearpc output."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def emulate(count: int = 1) -> str:
        """Show emulated disassembly from $pc without running the inferior.

        Args:
            count: Number of instruction lines from $pc onward.
                   Pwndbg may also show earlier instructions from its cache.
        """
        try:
            gdb = await get_controller()
            responses = await gdb.execute_console(f"emulate $pc {count}")
            return format_console_output(responses) or "No emulate output."
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Session
    # ===================================================================

    @mcp.tool()
    async def pwndbg_status() -> str:
        """Return the current GDB state and drain any pending messages."""
        try:
            gdb = await get_controller()
            from .gdb_controller import GdbState

            pending_output = ""
            if gdb.state == GdbState.RUNNING:
                responses = await gdb.get_responses()
                pending_output = format_console_output(responses)
            result = f"GDB state: {gdb.state.value}"
            if pending_output.strip():
                result += "\n\nPending messages:\n" + pending_output
            return result
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def pwndbg_hard_reset() -> str:
        """Kill and restart the GDB process completely. Use when GDB is stuck or crashed."""
        try:
            from .server import reset_controller

            result = await reset_controller()
            return result
        except Exception as e:
            return format_error(e)

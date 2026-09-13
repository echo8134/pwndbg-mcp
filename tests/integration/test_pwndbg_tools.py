"""Test pwndbg inspection on a stopped local C program."""

import ast
import asyncio
import re
import shutil
import subprocess

import pytest
import pytest_asyncio
from mcp.server.fastmcp import FastMCP

from src.gdb_controller import AsyncGdbController, GdbState
from src.tools_gdb import register_gdb_tools
from src.tools_pwndbg import register_pwndbg_tools


async def call_tool(mcp, name, **arguments):
    content, _ = await mcp.call_tool(name, arguments)
    return content[0].text


@pytest_asyncio.fixture
async def stopped_session(tmp_path, monkeypatch):
    executable = shutil.which("pwndbg")
    compiler = shutil.which("cc")
    if executable is None or compiler is None:
        pytest.skip("The pwndbg launcher and a C compiler are required")
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    source = tmp_path / "inspection.c"
    source.write_text(
        "volatile int marker = 7;\n"
        "int main(void) {\n"
        "    marker += 3;\n"
        "    marker += 5;\n"
        "    return marker;\n"
        "}\n"
    )
    binary = tmp_path / "inspection"
    subprocess.run([compiler, "-g", "-O0", str(source), "-o", str(binary)], check=True)
    gdb = AsyncGdbController(gdb_path=executable)
    mcp = FastMCP("test")

    async def get_controller():
        return gdb

    register_gdb_tools(mcp, get_controller)
    register_pwndbg_tools(mcp, get_controller)
    try:
        await gdb.start()
        # Disable automatic context so it does not mix with command output.
        result = await call_tool(mcp, "execute_command", command="set context-sections ''")
        assert "Error:" not in result, result
        result = await call_tool(mcp, "load_binary", path=str(binary))
        assert "Error:" not in result, result
        result = await call_tool(mcp, "run_program", stop_at_main=True)
        assert "Error:" not in result, result
        for _ in range(30):
            if gdb.state == GdbState.STOPPED:
                break
            await gdb.get_responses(timeout_sec=0.1)
            await asyncio.sleep(0)
        assert gdb.state == GdbState.STOPPED, result
        # Require the installed launcher to load pwndbg and its emulator.
        support = await call_tool(
            mcp, "execute_command",
            command="python import pwndbg.emu.emulator; print('emulation available')",
        )
        assert support.strip() == "emulation available", support
        yield mcp, gdb
    finally:
        await gdb.close()
        gdb._executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_emulate_inspects_pc_without_changing_inferior(stopped_session):
    mcp, gdb = stopped_session
    pc_result = await call_tool(mcp, "evaluate_expression", expression="$pc")
    pc = int(ast.literal_eval(pc_result)["value"].split()[0], 16)
    registers_before = await call_tool(mcp, "read_registers")
    stack_before = await call_tool(mcp, "read_memory", address="$sp", count=64)
    marker_before = await call_tool(mcp, "read_memory", address="&marker", count=4)
    for output in (registers_before, stack_before, marker_before):
        assert "Error:" not in output and output.startswith("{"), output

    for count in (1, 3):
        output = await call_tool(mcp, "emulate", count=count)
        assert "Error:" not in output, output
        # Instruction rows may start with a current-PC or breakpoint marker.
        addresses = re.findall(r"^\s*[b►]*\s*(0x[0-9a-f]+)\s+<", output, re.MULTILINE)
        assert len(addresses) == count, output
        assert int(addresses[0], 16) == pc, output
        assert "main" in output, output
        assert gdb.state == GdbState.STOPPED
        assert await call_tool(mcp, "read_registers") == registers_before
        assert await call_tool(mcp, "read_memory", address="$sp", count=64) == stack_before
        assert await call_tool(mcp, "read_memory", address="&marker", count=4) == marker_before

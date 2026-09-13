from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp import FastMCP

from src.gdb_controller import AsyncGdbController, GdbState
from src.tools_pwndbg import register_pwndbg_tools


@pytest.fixture
def tool_session():
    gdb = AsyncMock(spec=AsyncGdbController)
    gdb.state = GdbState.STOPPED
    gdb.execute_console.return_value = [{"type": "console", "payload": "output"}]
    mcp = FastMCP("test")
    register_pwndbg_tools(mcp, AsyncMock(return_value=gdb))
    return mcp, gdb


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool,address,count,command",
    [
        ("telescope", "", 1, "telescope $sp 1"),
        ("telescope", "", 3, "telescope $sp 3"),
        ("telescope", "0x1234", 2, "telescope 0x1234 2"),
        ("hexdump_memory", "", 16, "hexdump $sp 16"),
        ("hexdump_memory", "", 32, "hexdump $sp 32"),
        ("hexdump_memory", "0x1234", 16, "hexdump 0x1234 16"),
        ("nearpc", "", 1, "nearpc $pc 1"),
        ("nearpc", "", 3, "nearpc $pc 3"),
        ("nearpc", "main", 2, "nearpc main 2"),
        ("probeleak", "", 0, "probeleak $sp"),
        ("probeleak", "", 32, "probeleak $sp 32"),
        ("probeleak", "0x1234", 16, "probeleak 0x1234 16"),
    ],
)
async def test_inspection_forwards_address_and_count(tool_session, tool, address, count, command):
    mcp, gdb = tool_session
    await mcp.call_tool(tool, {"address": address, "count": count})
    gdb.execute_console.assert_awaited_once_with(command)


@pytest.mark.asyncio
@pytest.mark.parametrize("event", ["stopped", "thread-group-exited"])
@pytest.mark.parametrize("console_output", ["", "Inferior exited normally.\n"])
async def test_status_reflects_pending_events(tool_session, event, console_output):
    mcp, gdb = tool_session
    gdb.state = GdbState.RUNNING

    async def pending_responses():
        gdb.state = GdbState.STOPPED
        responses = [{"type": "notify", "message": event, "payload": None}]
        if console_output:
            responses.append({"type": "console", "payload": console_output})
        return responses

    gdb.get_responses.side_effect = pending_responses
    content, _ = await mcp.call_tool("pwndbg_status", {})
    output = content[0].text
    assert output.startswith("GDB state: stopped")
    assert ("Pending messages:" in output) == bool(console_output)
    if console_output:
        assert console_output.strip() in output


@pytest.mark.asyncio
async def test_status_keeps_running_when_no_stop_is_pending(tool_session):
    mcp, gdb = tool_session
    gdb.state = GdbState.RUNNING
    gdb.get_responses.return_value = []
    content, _ = await mcp.call_tool("pwndbg_status", {})
    assert content[0].text == "GDB state: running"


@pytest.mark.asyncio
async def test_status_omits_blank_pending_messages(tool_session):
    mcp, gdb = tool_session
    gdb.state = GdbState.RUNNING
    gdb.get_responses.return_value = [
        {"type": "console", "payload": "\n"},
        {"type": "console", "payload": " \n"},
    ]
    content, _ = await mcp.call_tool("pwndbg_status", {})
    assert content[0].text == "GDB state: running"


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 3, 255, 256, 1024])
async def test_emulate_count_is_not_an_address(tool_session, count):
    mcp, gdb = tool_session
    await mcp.call_tool("emulate", {"count": count})
    gdb.execute_console.assert_awaited_once_with(f"emulate $pc {count}")


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,arguments", [
    ("telescope", {}), ("hexdump_memory", {}), ("nearpc", {}), ("emulate", {}),
])
@pytest.mark.parametrize("record,diagnostic", [
    ({"type": "result", "message": "error", "payload": {"msg": "Invalid address"}}, "Invalid address"),
    ({"type": "error", "payload": "GDB not started. Load a binary first."}, "GDB not started"),
])
async def test_inspection_errors_reach_mcp(tool_session, tool, arguments, record, diagnostic):
    mcp, gdb = tool_session
    gdb.execute_console.return_value = [record]
    content, _ = await mcp.call_tool(tool, arguments)
    assert content[0].text.startswith("Error: ")
    assert diagnostic in content[0].text

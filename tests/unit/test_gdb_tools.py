"""Test MCP tools with controlled GDB responses."""

from unittest.mock import AsyncMock, call

import pytest
from mcp.server.fastmcp import FastMCP

from src.gdb_controller import AsyncGdbController
from src.tools_gdb import register_gdb_tools


DONE = [{"type": "result", "message": "done", "payload": None}]
RUNNING = [{"type": "result", "message": "running", "payload": None}]
ERRORS = [
    [{"type": "result", "message": "error", "payload": {"msg": "Command failed"}}],
    [{"type": "error", "payload": "GDB process died"}],
]


@pytest.fixture
def tool_session():
    gdb = AsyncMock(spec=AsyncGdbController)
    gdb.execute.return_value = DONE.copy()
    gdb.execute_console.return_value = DONE.copy()
    gdb.drain_responses.return_value = []
    mcp = FastMCP("test")
    register_gdb_tools(mcp, AsyncMock(return_value=gdb))
    return mcp, gdb


async def call_tool(mcp, name, **arguments):
    content, _ = await mcp.call_tool(name, arguments)
    return content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize("responses", ERRORS)
@pytest.mark.parametrize("tool,arguments", [
    ("evaluate_expression", {"expression": "missing"}),
    ("read_registers", {"registers": "missing"}),
    ("read_memory", {"address": "0"}),
    ("stack_args", {}),
])
async def test_inspection_errors_reach_mcp(tool_session, tool, arguments, responses):
    mcp, gdb = tool_session
    gdb.execute.return_value = responses
    gdb.execute_console.return_value = responses
    result = await call_tool(mcp, tool, **arguments)
    assert result.startswith("Error: "), result
    assert "Command failed" in result or "GDB process died" in result


@pytest.mark.asyncio
@pytest.mark.parametrize("responses", ERRORS)
async def test_load_failure_does_not_set_arguments(tool_session, responses):
    mcp, gdb = tool_session
    gdb.execute.return_value = responses
    result = await call_tool(mcp, "load_binary", path="fixture", args="hello")
    assert result.startswith("Error: "), result
    gdb.execute_console.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,arguments", [
    ("load_binary", {"path": "fixture", "args": "hello"}),
    ("run_program", {"args": "hello", "stop_at_main": True}),
])
@pytest.mark.parametrize("responses", ERRORS)
async def test_argument_setup_failure_is_returned(tool_session, tool, arguments, responses):
    mcp, gdb = tool_session
    gdb.execute_console.return_value = responses
    result = await call_tool(mcp, tool, **arguments)
    assert "Error: " in result, result
    assert "Loaded" not in result and "Program started" not in result
    if tool == "run_program":
        gdb.execute.assert_not_awaited()
    else:
        gdb.execute.assert_awaited_once_with('-file-exec-and-symbols "fixture"')
    gdb.drain_responses.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_failure_preserves_setup_context_and_skips_drain(tool_session):
    mcp, gdb = tool_session
    gdb.execute_console.return_value = [
        {"type": "console", "payload": "Argument setup context\n"}, *DONE,
    ]
    gdb.execute.return_value = ERRORS[0]
    result = await call_tool(mcp, "run_program", args="hello", stop_at_main=True)
    assert result == "Argument setup context\nError: Command failed"
    assert gdb.mock_calls == [
        call.execute_console("set args hello"), call.execute("-exec-run --start"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,arguments,acknowledgement", [
    ("load_binary", {"path": "fixture", "args": "hello"}, "Loaded fixture"),
    ("run_program", {"args": "hello"}, "Program started."),
    ("select_frame", {"number": 1}, "Selected frame 1."),
    ("detach_process", {}, "Detached."),
])
async def test_empty_success_acknowledgements(tool_session, tool, arguments, acknowledgement):
    mcp, gdb = tool_session
    if tool == "run_program":
        gdb.execute.return_value = RUNNING
    assert await call_tool(mcp, tool, **arguments) == acknowledgement


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,arguments", [
    ("load_binary", {"path": "fixture"}),
    ("run_program", {}),
    ("select_frame", {"number": 1}),
    ("detach_process", {}),
])
@pytest.mark.parametrize("responses", [[], [{"type": "notify", "message": "stopped"}]])
async def test_unacknowledged_commands_do_not_claim_success(tool_session, tool, arguments, responses):
    mcp, gdb = tool_session
    gdb.execute.return_value = responses
    result = await call_tool(mcp, tool, **arguments)
    assert "completion is unconfirmed" in result, result
    assert "timeout" not in result.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("tool,arguments", [
    ("load_binary", {"path": "fixture", "args": "hello"}),
    ("run_program", {"args": "hello"}),
])
async def test_earlier_acknowledgement_does_not_confirm_later_command(tool_session, tool, arguments):
    mcp, gdb = tool_session
    if tool == "load_binary":
        gdb.execute_console.return_value = []
    else:
        gdb.execute.return_value = []
    result = await call_tool(mcp, tool, **arguments)
    assert "completion is unconfirmed" in result, result


@pytest.mark.asyncio
async def test_ordinary_error_text_does_not_block_run(tool_session):
    mcp, gdb = tool_session
    gdb.execute_console.return_value = [{"type": "console", "payload": "error_count = 0"}, *DONE]
    gdb.execute.return_value = RUNNING
    result = await call_tool(mcp, "run_program", args="hello")
    gdb.execute.assert_awaited_once_with("-exec-run")
    assert "Error:" not in result

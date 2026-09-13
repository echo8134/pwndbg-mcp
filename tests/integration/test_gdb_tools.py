"""GDB tool regression tests with a compiled C program."""

import asyncio
import shutil
import subprocess

import pytest
import pytest_asyncio
from mcp.server.fastmcp import FastMCP

from src.gdb_controller import AsyncGdbController, GdbState
from src.tools_gdb import register_gdb_tools


@pytest.fixture(scope="module")
def program(tmp_path_factory):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("A C compiler is required for GDB integration tests")
    directory = tmp_path_factory.mktemp("gdb-tools")
    source = directory / "fixture.c"
    source.write_text(
        "__attribute__((noinline)) int inner(int inner_value) {\n"
        "    return inner_value + 1;\n"
        "}\n"
        "__attribute__((noinline)) int outer(int outer_value) {\n"
        "    return inner(outer_value + 10);\n"
        "}\n"
        "int main(void) {\n"
        "    return outer(7) == 18 ? 0 : 1;\n"
        "}\n"
    )
    binary = directory / "fixture"
    subprocess.run([compiler, "-g", "-O0", str(source), "-o", str(binary)], check=True)
    return binary


@pytest_asyncio.fixture
async def tool_session(monkeypatch):
    executable = shutil.which("gdb")
    if executable is None:
        pytest.skip("GDB is required for GDB integration tests")
    monkeypatch.setenv("DEBUGINFOD_URLS", "")
    gdb = AsyncGdbController(gdb_path=executable)
    mcp = FastMCP("test")

    async def get_controller():
        return gdb

    register_gdb_tools(mcp, get_controller)
    try:
        await gdb.start()
        yield mcp, gdb
    finally:
        await gdb.close()
        gdb._executor.shutdown(wait=True)


async def call_tool(mcp, name, **arguments):
    content, _ = await mcp.call_tool(name, arguments)
    return content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filename",
    ["with spaces", 'with "quotes"', r"with\backslash", "café", "with\ttab", "with\x01control"],
)
async def test_load_binary_preserves_filename(tool_session, program, tmp_path, filename):
    mcp, gdb = tool_session
    path = tmp_path / filename
    shutil.copy2(program, path)
    result = await call_tool(mcp, "load_binary", path=str(path))
    assert "Loaded " in result, result
    # Check GDB's symbol data as well as the tool's response.
    responses = await gdb.execute("-file-list-exec-source-file")
    assert any(r.get("payload", {}).get("file", "").endswith("fixture.c")
               for r in responses if isinstance(r.get("payload"), dict)), responses


@pytest.mark.asyncio
async def test_stack_args_follows_selected_frame(tool_session, program):
    mcp, gdb = tool_session
    await call_tool(mcp, "load_binary", path=str(program))
    await call_tool(mcp, "set_breakpoint", location="inner")
    run_result = await call_tool(mcp, "run_program")
    for _ in range(20):
        if gdb.state == GdbState.STOPPED:
            break
        await gdb.get_responses(timeout_sec=0.1)
        await asyncio.sleep(0)
    assert gdb.state == GdbState.STOPPED, run_result
    assert "inner_value" in await call_tool(mcp, "stack_args")
    await call_tool(mcp, "select_frame", number=1)
    arguments = await call_tool(mcp, "stack_args")
    assert "outer_value" in arguments, arguments
    assert "inner_value" not in arguments, arguments

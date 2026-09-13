"""Strip ANSI escapes and format debugger output."""

from __future__ import annotations

import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\x1b\[.*?[@-~]")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_RE.sub("", text)


def _is_error_response(response: dict[str, object]) -> bool:
    return response.get("type") == "error" or (
        response.get("type") == "result" and response.get("message") == "error"
    )


def has_response_error(responses: list[dict[str, object]]) -> bool:
    """Recognize explicit protocol errors without interpreting console text."""
    return any(_is_error_response(response) for response in responses)


def _format_response_error(response: dict[str, object]) -> str:
    payload = response.get("payload")
    if isinstance(payload, dict) and "msg" in payload:
        payload = payload["msg"]
    message = strip_ansi(str(payload)).strip() if payload is not None else ""
    if not message or payload == {} or payload == []:
        message = "GDB command failed (no error message provided)."
    return f"Error: {message}"


def format_responses(responses: list[dict[str, object]]) -> str:
    """Format GDB/MI responses as plain text.

    Includes console output, result payloads, and explicit MI and controller errors.
    """
    lines: list[str] = []
    for resp in responses:
        if _is_error_response(resp):
            lines.append(_format_response_error(resp))
            continue
        msg_type = resp.get("type")
        payload = resp.get("payload")
        if payload is None:
            continue
        if msg_type == "console":
            lines.append(strip_ansi(str(payload)).rstrip())
        elif msg_type == "result":
            if isinstance(payload, dict):
                lines.append(str(payload))
            elif isinstance(payload, str) and payload != "done":
                lines.append(strip_ansi(payload).rstrip())
    return "\n".join(lines)


def format_console_output(responses: list[dict[str, object]]) -> str:
    """Format output from pwndbg and other console commands.

    Includes console, log, target, and output streams, structured results, and
    explicit MI and controller errors.
    """
    lines: list[str] = []
    for resp in responses:
        if _is_error_response(resp):
            lines.append(_format_response_error(resp))
        elif resp.get("type") in ("console", "log", "output", "target"):
            payload = resp.get("payload")
            if payload is not None:
                lines.append(strip_ansi(str(payload)).rstrip())
        elif resp.get("type") == "result" and isinstance(resp.get("payload"), dict):
            lines.append(str(resp["payload"]))
    return "\n".join(lines)


def format_error(e: Exception) -> str:
    """Format an exception as an error string for tool output."""
    return f"Error: {type(e).__name__}: {e}"

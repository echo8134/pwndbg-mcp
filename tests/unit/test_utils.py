import pytest

from src.utils import strip_ansi, format_responses, format_console_output, format_error


def test_strip_ansi_removes_color_codes():
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_strip_ansi_passthrough_clean():
    assert strip_ansi("clean text") == "clean text"


def test_strip_ansi_complex_sequences():
    assert strip_ansi("\x1b[1;32;40mbold green\x1b[0m") == "bold green"


def test_format_responses_console():
    responses = [{"type": "console", "payload": "hello\n"}]
    assert "hello" in format_responses(responses)


def test_format_responses_result_dict():
    responses = [{"type": "result", "payload": {"key": "val"}}]
    result = format_responses(responses)
    assert "key" in result


def test_format_responses_skips_none_payload():
    responses = [{"type": "console", "payload": None}]
    assert format_responses(responses) == ""


def test_format_responses_multiple():
    responses = [
        {"type": "console", "payload": "line1"},
        {"type": "console", "payload": "line2"},
    ]
    result = format_responses(responses)
    assert "line1" in result
    assert "line2" in result


def test_format_console_output_console_and_log():
    responses = [
        {"type": "console", "payload": "console line"},
        {"type": "log", "payload": "log line"},
        {"type": "result", "payload": "hidden"},
    ]
    result = format_console_output(responses)
    assert "console line" in result
    assert "log line" in result
    assert "hidden" not in result


def test_format_error():
    result = format_error(ValueError("bad"))
    assert "ValueError" in result
    assert "bad" in result


@pytest.mark.parametrize("formatter", [format_responses, format_console_output])
@pytest.mark.parametrize(
    "record,diagnostic",
    [
        ({"type": "result", "message": "error", "payload": {"msg": "Invalid expression"}},
         "Invalid expression"),
        ({"type": "error", "payload": "GDB not started. Load a binary first."},
         "GDB not started. Load a binary first."),
        ({"type": "error", "payload": "GDB process died. Use pwndbg_hard_reset() to restart."},
         "GDB process died. Use pwndbg_hard_reset() to restart."),
        ({"type": "error", "payload": {"msg": "\x1b[31mbad\x1b[0m"}}, "bad"),
        ({"type": "result", "message": "error", "payload": "bad request"}, "bad request"),
        ({"type": "error", "payload": {"detail": "unusual failure"}}, "unusual failure"),
        ({"type": "error", "payload": ["unexpected", 7]}, "unexpected"),
        ({"type": "error", "payload": 42}, "42"),
    ],
)
def test_explicit_errors_keep_diagnostic_context(formatter, record, diagnostic):
    result = formatter([{"type": "console", "payload": "\x1b[32mcontext\x1b[0m\n"}, record])
    assert result.startswith("context\nError: "), result
    assert diagnostic in result
    assert "\x1b" not in result


@pytest.mark.parametrize("formatter", [format_responses, format_console_output])
@pytest.mark.parametrize("kind", ["error", "result"])
@pytest.mark.parametrize("payload", [None, "", " \n", {}, {"msg": None}, {"msg": ""}, []])
def test_errors_without_a_message_have_a_generic_diagnostic(formatter, kind, payload):
    result = formatter([{"type": kind, "message": "error", "payload": payload}])
    assert result == "Error: GDB command failed (no error message provided)."


@pytest.mark.parametrize("formatter", [format_responses, format_console_output])
def test_error_with_absent_payload(formatter):
    assert formatter([{"type": "result", "message": "error"}]).startswith("Error: GDB command failed")


@pytest.mark.parametrize("formatter", [format_responses, format_console_output])
def test_ordinary_error_text_is_preserved(formatter):
    assert formatter([{"type": "console", "payload": "error_count = 0\n"}]) == "error_count = 0"


@pytest.mark.parametrize("formatter", [format_responses, format_console_output])
def test_successful_structured_result_remains_readable(formatter):
    assert formatter([{"type": "result", "message": "done", "payload": {"value": "42"}}]) == "{'value': '42'}"


def test_console_streams_keep_ansi_cleanup():
    responses = [{"type": kind, "payload": "\x1b[31mtext\x1b[0m\n"}
                 for kind in ("console", "log", "target", "output")]
    assert format_console_output(responses) == "text\ntext\ntext\ntext"

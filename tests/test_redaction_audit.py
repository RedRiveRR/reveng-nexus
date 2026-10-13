import json

from reveng_nexus.audit import AuditLog
from reveng_nexus.errors import NexusError, describe_exception
from reveng_nexus.redaction import redact_mapping, redact_text


def test_redacts_common_secret_shapes():
    text = (
        "Authorization: Bearer abcdefghijklmnop123 api_key=sk-proj-1234567890abcdefghij "
        "url=https://user:hunter2@example.org/x password: 'p@ss' ghp_abcdefghijklmnopqrstuvwxyz AKIAABCDEFGHIJKLMNOP"
    )
    out = redact_text(text)
    for secret in (
        "abcdefghijklmnop123",
        "sk-proj-1234567890",
        "hunter2",
        "p@ss",
        "ghp_abcdefghijklmnop",
        "AKIAABCDEFGHIJKLMNOP",
    ):
        assert secret not in out, secret
    assert "[REDACTED" in out


def test_redact_mapping_by_key():
    out = redact_mapping({"OPENAI_API_KEY": "x", "nested": {"token": "y", "path": "/tmp"}, "PATH": "/bin"})
    assert out["OPENAI_API_KEY"] == "[REDACTED]"
    assert out["nested"]["token"] == "[REDACTED]" and out["nested"]["path"] == "/tmp"
    assert out["PATH"] == "/bin"


def test_errors_are_redacted_and_bounded():
    err = NexusError("failed with token=supersecretvalue " + "x" * 5000)
    payload = err.to_dict()
    assert "supersecretvalue" not in payload["message"]
    assert len(payload["message"]) <= 2000
    generic = describe_exception(RuntimeError("password=abc123"))
    assert "abc123" not in generic["message"]


def test_audit_log_is_metadata_only(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.write(
        "tool_call",
        provider_id="p",
        tool_name="decompile_function",
        argument_keys=["address", "database"],
        outcome="ok",
        error="api_key=sk-test-1234567890abcdef",
        arguments={"address": "0x401000"},
        code="int main() { return SECRET; }",
    )
    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    record = json.loads(line)
    assert record["argument_keys"] == ["address", "database"]
    assert "0x401000" not in line and "SECRET" not in line, "values and code never reach the audit log"
    assert "sk-test" not in line
    assert log.tail(5)[0]["tool_name"] == "decompile_function"


def test_audit_write_failure_does_not_raise(tmp_path):
    target = tmp_path / "dir_instead_of_file"
    target.mkdir()
    log = AuditLog(target)
    log.write("x")
    assert log.write_failures == 1

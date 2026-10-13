import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
EXAMPLE = ROOT / "config" / "providers.example.yaml"


def run(*args, cwd=None):
    proc = subprocess.run(
        [sys.executable, "-m", "reveng_nexus", *args], capture_output=True, text=True, timeout=180, cwd=cwd
    )
    return proc.returncode, proc.stdout, proc.stderr


def write_config(tmp_path, workspace, providers=None):
    cfg = tmp_path / "config" / "providers.yaml"
    cfg.parent.mkdir(exist_ok=True)
    cfg.write_text(
        yaml.safe_dump(
            {
                "workspace": {"allowed_roots": [str(workspace)], "data_dir": str(tmp_path / "data")},
                "providers": providers or [],
            }
        ),
        encoding="utf-8",
    )
    return cfg


def test_check_config_on_example():
    code, out, _ = run("--config", str(EXAMPLE), "--check-config")
    assert code == 0 and "Config valid" in out and "enabled: ['builtin']" in out
    code, out, _ = run("--config", str(EXAMPLE), "config", "check")
    assert code == 0


def test_bad_config_exits_2(tmp_path):
    bad = tmp_path / "providers.yaml"
    bad.write_text("providers: [{id: X}]", encoding="utf-8")
    code, _, err = run("--config", str(bad), "--check-config")
    assert code == 2 and "Configuration error" in err


def test_providers_list_shows_upstream_pins():
    code, out, _ = run("--config", str(EXAMPLE), "providers", "list")
    rows = {r["id"]: r for r in json.loads(out)}
    assert code == 0
    assert rows["ghidra_remcp"]["upstream"]["verification"] == "runtime"
    assert rows["jadx"]["upstream"]["verification"] == "source"


def test_status_no_start():
    code, out, _ = run("--config", str(EXAMPLE), "status", "--no-start")
    assert code == 0 and json.loads(out)["read_only"] is True


def test_providers_check_reports_missing_engines_without_crashing(tmp_path, workspace):
    cfg = write_config(
        tmp_path, workspace, [{"id": "ghost", "enabled": True, "command": "no-such-engine-xyz", "adapter": "re_mcp"}]
    )
    code, out, _ = run("--config", str(cfg), "providers", "check")
    report = json.loads(out)
    assert code == 1, "an enabled provider that cannot start fails the check"
    assert report["builtin"]["health"]["status"] == "ready"
    assert "was not found" in report["ghost"]["error"]


def test_analyze_and_report_builtin_only(tmp_path, workspace, elf_sample):
    cfg = write_config(tmp_path, workspace)
    code, out, err = run("--config", str(cfg), "analyze", str(elf_sample), "--case-title", "CLI case")
    assert code == 0, err
    result = json.loads(out)
    case_id = result["target"]["case_id"]
    assert result["analysis"]["missing_capabilities"][0]["capability"] == "binary.decompile"
    code, out, _ = run("--config", str(cfg), "report", case_id, "--out", str(tmp_path / "rep"))
    assert code == 0
    files = json.loads(out)["files"]
    assert Path(files["md"]).read_text(encoding="utf-8").startswith("# RevEng Nexus report — CLI case")


def test_capabilities_command(tmp_path, workspace):
    cfg = write_config(tmp_path, workspace)
    code, out, _ = run("--config", str(cfg), "capabilities")
    assert code == 0 and "binary.metadata" in out and "builtin" in out


def test_config_init_generates_validated_config(tmp_path, workspace):
    out_file = tmp_path / "config" / "providers.yaml"
    code, out, err = run(
        "config",
        "init",
        "--workspace",
        str(workspace),
        "--enable",
        "ghidra_remcp",
        "--ghidra-dir",
        str(tmp_path),
        "--output",
        str(out_file),
        "--example",
        str(EXAMPLE),
    )
    assert code == 0, err
    data = yaml.safe_load(out_file.read_text(encoding="utf-8"))
    enabled = {p["id"] for p in data["providers"] if p.get("enabled")}
    assert enabled == {"builtin", "ghidra_remcp"}
    remcp = next(p for p in data["providers"] if p["id"] == "ghidra_remcp")
    assert remcp["env"]["GHIDRA_INSTALL_DIR"] == str(tmp_path.resolve())
    code, _, err = run(
        "config", "init", "--workspace", str(workspace), "--output", str(out_file), "--example", str(EXAMPLE)
    )
    assert code == 2 and "exists" in err
    code, out, _ = run("--config", str(out_file), "--check-config")
    assert code == 0


def test_check_config_diagnoses_missing_paths_and_tools(tmp_path):
    cfg = tmp_path / "providers.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "workspace": {"allowed_roots": [str(tmp_path / "no-such-samples")], "data_dir": str(tmp_path / "data")},
                "providers": [
                    {
                        "id": "gh",
                        "enabled": True,
                        "command": "no-such-engine-xyz",
                        "adapter": "re_mcp",
                        "env": {"GHIDRA_INSTALL_DIR": str(tmp_path / "no-ghidra")},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    code, out, _ = run("--config", str(cfg), "--check-config")
    assert code == 1, "a missing workspace root is an error"
    assert "allowed root does not exist" in out
    assert "executable not found: no-such-engine-xyz" in out
    assert "GHIDRA_INSTALL_DIR points to a missing directory" in out
    assert not (tmp_path / "data").exists(), "diagnostics must not create directories"


def test_config_init_create_dirs(tmp_path):
    ws, data, out_file = tmp_path / "ws", tmp_path / "appdata" / "data", tmp_path / "config" / "providers.yaml"
    code, _, err = run(
        "config",
        "init",
        "--workspace",
        str(ws),
        "--data-dir",
        str(data),
        "--output",
        str(out_file),
        "--example",
        str(EXAMPLE),
    )
    assert code == 2 and "--create-dirs" in err
    code, _, err = run(
        "config",
        "init",
        "--workspace",
        str(ws),
        "--data-dir",
        str(data),
        "--create-dirs",
        "--output",
        str(out_file),
        "--example",
        str(EXAMPLE),
    )
    assert code == 0, err
    assert ws.is_dir() and data.is_dir()
    code, out, _ = run("--config", str(out_file), "--check-config")
    assert code == 0 and str(data) in out


def test_serve_http_refuses_non_loopback_bind():
    code, _, err = run("--config", str(EXAMPLE), "serve", "--transport", "http", "--host", "0.0.0.0", "--port", "8799")
    assert code == 2 and "Refusing to serve HTTP" in err and "Traceback" not in err

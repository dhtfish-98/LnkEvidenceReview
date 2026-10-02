"""Run from a fresh consumer interpreter; fixtures remain outside the installed package."""

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import lnk_evidence_review


def main():
    source = Path(__file__).resolve().parents[1]
    installed = Path(lnk_evidence_review.__file__).resolve().parent
    assert installed != source / "src/lnk_evidence_review", (
        "source_import_instead_of_installed_package"
    )
    assert Path(sys.prefix).resolve() in installed.parents and "site-packages" in installed.parts
    assert importlib.metadata.version("lnk-evidence-review") == "0.1.0"
    checked = []
    for path in sorted((source / "src/lnk_evidence_review").glob("*")):
        if not path.is_file():
            continue
        actual = installed / path.name
        assert path.read_bytes() == actual.read_bytes(), path.name
        checked.append(
            {"file": path.name, "sha256": hashlib.sha256(actual.read_bytes()).hexdigest()}
        )
    env = dict(os.environ, PYTHONPATH="", PYTHONDONTWRITEBYTECODE="1")
    sys.path.insert(0, str(source / "tests"))
    from fixtures import counted, environment, header, property_store, typed, u32

    cases = []
    with tempfile.TemporaryDirectory(
        dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"
    ) as folder:
        cwd = Path(folder)
        target = cwd / "PRIVATE_名字.lnk"
        fixtures = (
            ("minimal", header() + u32(0), [], 0),
            ("malformed", b"bad", [], 1),
            ("unknown", header() + u32(8) + u32(0x1234) + u32(0), [], 2),
            ("unicode", header(0xA0) + counted("SECRET_名字 & cmd\n") + u32(0), [], 0),
            (
                "disclose",
                header(0xA0) + counted("SECRET_名字 & cmd\n") + u32(0),
                ["--show-text"],
                0,
            ),
            ("environment", header(0x200) + environment() + u32(0), [], 0),
            ("property", header() + property_store([(1, typed(3, u32(42)))]) + u32(0), [], 0),
            (
                "report_cap",
                header(0xA0) + counted("SECRET_" * 1000) + u32(0),
                ["--show-text", "--report-bytes", "2048"],
                2,
            ),
            ("input_cap", header() + u32(0), ["--input-bytes", "1"], 2),
        )
        command = Path(sys.executable).parent / "lnk-evidence-review"
        for name, data, flags, expected in fixtures:
            target.write_bytes(data)
            for prefix in ([sys.executable, "-m", "lnk_evidence_review"], [str(command)]):
                result = subprocess.run(
                    [*prefix, str(target), *flags],
                    cwd=cwd,
                    env=env,
                    capture_output=True,
                    check=False,
                )
                assert result.returncode == expected, (name, result.returncode, result.stderr)
                assert result.stderr == b"", name
                report = json.loads(result.stdout)
                assert target.read_bytes() == data
                assert b"PRIVATE_" not in result.stdout
                if "--show-text" not in flags:
                    assert b"SECRET_" not in result.stdout
                assert all(value == "OPEN" for value in report["assumptions"].values())
                cases.append(
                    {
                        "case": name,
                        "entry": "module" if len(prefix) > 1 else "installed_script",
                        "exit": result.returncode,
                        "status": report["status"],
                    }
                )
        for arguments in (
            [],
            ["--unknown", "PRIVATE_PATH"],
            ["PRIVATE_PATH", "--input-bytes", "²"],
            ["PRIVATE_PATH", "--report-bytes", "2047"],
        ):
            result = subprocess.run(
                [str(command), *arguments], cwd=cwd, env=env, capture_output=True, check=False
            )
            assert result.returncode == 2 and result.stderr == b""
            assert b"PRIVATE_PATH" not in result.stdout
            assert json.loads(result.stdout)["findings"][0]["code"] == "invalid_arguments"
            cases.append(
                {
                    "case": "invalid_arguments",
                    "entry": "installed_script",
                    "exit": 2,
                    "status": "OPEN",
                }
            )
        target.write_bytes(header() + u32(0))
        frozen = target.read_bytes()
        assert lnk_evidence_review.review_bytes(frozen)["status"] == "PASS"
        assert frozen == target.read_bytes()
    return {
        "installed_runtime": checked,
        "cli_cases": cases,
        "cases": len(cases),
        "api_input_unchanged": True,
    }


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))

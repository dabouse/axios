from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    """Encapsulate command execution outputs for reliable diagnostics."""

    exit_code: int
    stdout: str
    stderr: str


class SafeCommandRunner:
    """Execute external commands with strict error capture."""

    @staticmethod
    def run(command: list[str], cwd: Path | None = None) -> CommandResult:
        try:
            result: subprocess.CompletedProcess[str] = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                check=False,
            )
            return CommandResult(
                exit_code=result.returncode,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
            )
        except FileNotFoundError as exc:
            return CommandResult(exit_code=127, stdout="", stderr=str(exc))
        except Exception as exc:  # noqa: BLE001
            return CommandResult(exit_code=1, stdout="", stderr=f"Execution error: {exc}")


class CrossPlatformIoCScanner:
    """Detect lightweight IoCs adapted to each operating system."""

    IOC_PATTERN = re.compile(r"(wt\.exe|ld\.py|plain-crypto-js|axios)", re.IGNORECASE)

    def __init__(self, system_name: str) -> None:
        self._system_name: str = system_name

    def scan(self) -> dict[str, Any]:
        if self._system_name == "Windows":
            return self._scan_windows()
        if self._system_name == "Darwin":
            return self._scan_macos()
        if self._system_name == "Linux":
            return self._scan_linux()
        return {"platform": self._system_name, "supported": False, "notes": ["Unsupported platform."]}

    def _scan_windows(self) -> dict[str, Any]:
        program_data: str = os.environ.get("PROGRAMDATA", "")
        wt_path: Path = Path(program_data) / "wt.exe" if program_data else Path("C:/ProgramData/wt.exe")

        startup_candidates: list[Path] = [
            Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
            Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
        ]
        startup_hits: list[str] = self._scan_paths_for_pattern(startup_candidates)
        run_key_notes: list[str] = [
            "Use security-check-all.ps1 for full Run keys enumeration on Windows."
        ]

        return {
            "platform": "Windows",
            "supported": True,
            "programdata_wt_exe_found": wt_path.exists(),
            "programdata_wt_exe_path": str(wt_path),
            "suspicious_startup_entries": startup_hits,
            "notes": run_key_notes,
        }

    def _scan_macos(self) -> dict[str, Any]:
        launch_agents: list[Path] = [
            Path.home() / "Library/LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        hits: list[str] = self._scan_paths_for_pattern(launch_agents)

        suspicious_files: list[Path] = [
            Path("/tmp/wt"),
            Path("/usr/local/bin/wt"),
            Path.home() / ".local/bin/wt",
        ]
        existing_suspicious: list[str] = [str(path) for path in suspicious_files if path.exists()]

        return {
            "platform": "macOS",
            "supported": True,
            "suspicious_autostart_entries": hits,
            "suspicious_files_found": existing_suspicious,
        }

    def _scan_linux(self) -> dict[str, Any]:
        autostart_locations: list[Path] = [
            Path.home() / ".config/autostart",
            Path("/etc/xdg/autostart"),
            Path("/etc/systemd/system"),
            Path.home() / ".config/systemd/user",
        ]
        hits: list[str] = self._scan_paths_for_pattern(autostart_locations)

        suspicious_files: list[Path] = [
            Path("/tmp/wt"),
            Path("/usr/local/bin/wt"),
            Path.home() / ".local/bin/wt",
        ]
        existing_suspicious: list[str] = [str(path) for path in suspicious_files if path.exists()]

        return {
            "platform": "Linux",
            "supported": True,
            "suspicious_autostart_entries": hits,
            "suspicious_files_found": existing_suspicious,
        }

    def _scan_paths_for_pattern(self, paths: list[Path]) -> list[str]:
        matches: list[str] = []
        for base_path in paths:
            if not base_path.exists():
                continue
            try:
                for file_path in base_path.rglob("*"):
                    if not file_path.is_file():
                        continue
                    if self._file_looks_suspicious(file_path):
                        matches.append(str(file_path))
            except Exception:
                matches.append(f"{base_path} (permission denied or unreadable)")
        return sorted(set(matches))

    def _file_looks_suspicious(self, path: Path) -> bool:
        if self.IOC_PATTERN.search(path.name):
            return True
        try:
            content: str = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False
        return bool(self.IOC_PATTERN.search(content))


class CrossPlatformSecurityChecker:
    """Orchestrate Axios scan + OS IoC checks and generate reports."""

    def __init__(self, root_path: Path, output_dir: Path) -> None:
        self._root_path: Path = root_path
        self._output_dir: Path = output_dir
        self._system_name: str = platform.system()

    def run(self) -> tuple[int, Path, Path]:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        timestamp: str = datetime.now().strftime("%Y%m%d-%H%M%S")
        txt_report_path: Path = self._output_dir / f"security-report-{timestamp}.txt"
        json_report_path: Path = self._output_dir / f"security-report-{timestamp}.json"

        axios_scan: dict[str, Any] = self._run_axios_scan()
        ioc_scan: dict[str, Any] = CrossPlatformIoCScanner(system_name=self._system_name).scan()

        has_axios_suspicion: bool = self._compute_axios_suspicion(axios_scan)
        has_os_ioc: bool = self._compute_os_ioc(ioc_scan)
        overall_safe: bool = not (has_axios_suspicion or has_os_ioc)

        report: dict[str, Any] = {
            "Metadata": {
                "GeneratedAt": datetime.now().isoformat(),
                "ComputerName": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown",
                "UserName": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
                "RootPath": str(self._root_path),
                "Platform": self._system_name,
            },
            "AxiosScan": axios_scan,
            "PlatformIoC": ioc_scan,
            "SystemSecurityAssessment": {
                "Available": False,
                "Message": "No unified cross-platform antivirus history collector configured.",
            },
            "FinalVerdict": {
                "Safe": overall_safe,
                "HasAxiosSuspicion": has_axios_suspicion,
                "HasPlatformIoC": has_os_ioc,
                "Message": (
                    "Aucun indicateur direct Axios/IoC OS detecte."
                    if overall_safe
                    else "Indicateur(s) Axios/IoC OS detecte(s). Isoler la machine et lancer une reponse a incident."
                ),
            },
        }

        txt_report_path.write_text(self._build_txt_report(report, json_report_path), encoding="utf-8")
        json_report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

        return (0 if overall_safe else 2), txt_report_path, json_report_path

    def _run_axios_scan(self) -> dict[str, Any]:
        script_path: Path = Path(__file__).parent / "axios1.py"
        if not script_path.exists():
            return {
                "ExitCode": 1,
                "Parsed": None,
                "Error": f"Impossible de trouver axios1.py a cote du script: {script_path}",
            }

        command: list[str] = [sys.executable, str(script_path), "--root", str(self._root_path), "--json"]
        result: CommandResult = SafeCommandRunner.run(command=command, cwd=Path(__file__).parent)

        parsed: dict[str, Any] | None = None
        parse_error: str | None = None
        if result.stdout:
            try:
                parsed_candidate: Any = json.loads(result.stdout)
                parsed = parsed_candidate if isinstance(parsed_candidate, dict) else {"raw": parsed_candidate}
            except json.JSONDecodeError as exc:
                parse_error = f"Impossible de parser la sortie JSON de axios1.py: {exc}"

        return {
            "ExitCode": result.exit_code,
            "Parsed": parsed,
            "RawStdErr": result.stderr,
            "ParseError": parse_error,
        }

    def _compute_axios_suspicion(self, axios_scan: dict[str, Any]) -> bool:
        parsed: Any = axios_scan.get("Parsed")
        if not isinstance(parsed, dict):
            return False
        projects: Any = parsed.get("projects")
        if not isinstance(projects, list):
            return False
        for project in projects:
            if not isinstance(project, dict):
                continue
            compromised: list[str] = project.get("compromised_versions_found", [])
            plain_crypto: bool = bool(project.get("plain_crypto_js_found", False))
            if len(compromised) > 0 or plain_crypto:
                return True
        return False

    def _compute_os_ioc(self, ioc_scan: dict[str, Any]) -> bool:
        if bool(ioc_scan.get("programdata_wt_exe_found", False)):
            return True
        suspicious_autostart: list[str] = ioc_scan.get("suspicious_autostart_entries", [])
        suspicious_startup: list[str] = ioc_scan.get("suspicious_startup_entries", [])
        suspicious_files: list[str] = ioc_scan.get("suspicious_files_found", [])
        return bool(suspicious_autostart or suspicious_startup or suspicious_files)

    def _build_txt_report(self, report: dict[str, Any], json_report_path: Path) -> str:
        metadata: dict[str, Any] = report["Metadata"]
        verdict: dict[str, Any] = report["FinalVerdict"]
        system_assessment: dict[str, Any] = report["SystemSecurityAssessment"]
        ioc_scan: dict[str, Any] = report["PlatformIoC"]

        lines: list[str] = [
            "Security check report",
            f"Generated at: {metadata['GeneratedAt']}",
            f"Computer: {metadata['ComputerName']}",
            f"User: {metadata['UserName']}",
            f"RootPath: {metadata['RootPath']}",
            f"Platform: {metadata['Platform']}",
            "",
            f"Final verdict: {verdict['Message']}",
            f"Flags: AxiosSuspicion={verdict['HasAxiosSuspicion']}, PlatformIoC={verdict['HasPlatformIoC']}",
            "",
            f"System security note: {system_assessment['Message']}",
            f"Platform IoC summary: {self._build_ioc_summary(ioc_scan)}",
            "",
            f"JSON report: {json_report_path}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _build_ioc_summary(ioc_scan: dict[str, Any]) -> str:
        if "programdata_wt_exe_found" in ioc_scan:
            return f"programdata_wt_exe_found={ioc_scan.get('programdata_wt_exe_found', False)}"
        autostart_count: int = len(ioc_scan.get("suspicious_autostart_entries", []))
        file_count: int = len(ioc_scan.get("suspicious_files_found", []))
        return f"suspicious_autostart_entries={autostart_count}, suspicious_files_found={file_count}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verification cross-platform Axios + IoC OS (Windows/macOS/Linux)."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home(),
        help="Dossier racine a scanner (defaut: dossier utilisateur).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Dossier de sortie des rapports (defaut: ./reports).",
    )
    return parser.parse_args()


def main() -> None:
    args: argparse.Namespace = parse_args()
    checker = CrossPlatformSecurityChecker(root_path=args.root, output_dir=args.output_dir)
    exit_code, txt_report_path, json_report_path = checker.run()

    print("\n=== Rapport genere ===")
    print(f"TXT  : {txt_report_path}")
    print(f"JSON : {json_report_path}")

    if exit_code == 0:
        print("\nAucun indicateur direct Axios/IoC OS detecte.")
    else:
        print("\nIndicateur(s) Axios/IoC OS detecte(s).")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

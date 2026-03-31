from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import textwrap
import venv
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    """Store process outputs to keep diagnostics explicit."""

    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ProjectFinding:
    """Represent findings for a single Node.js project."""

    project_path: str
    axios_versions: list[str]
    compromised_versions_found: list[str]
    plain_crypto_js_found: bool
    npm_errors: list[str]

    @property
    def is_suspicious(self) -> bool:
        return bool(self.compromised_versions_found or self.plain_crypto_js_found)


class ProgressBar:
    """Render a simple textual progress bar for long-running steps."""

    def __init__(self, title: str, total: int) -> None:
        self._title: str = title
        self._total: int = max(total, 1)
        self._current: int = 0
        self._width: int = 28
        print(f"[step] {self._title}")
        self.update(0)

    def update(self, increment: int = 1) -> None:
        self._current = min(self._current + increment, self._total)
        ratio: float = self._current / self._total
        filled: int = int(ratio * self._width)
        bar: str = ("#" * filled) + ("-" * (self._width - filled))
        percent: int = int(ratio * 100)
        print(f"\r    [{bar}] {percent:3d}% ({self._current}/{self._total})", end="", flush=True)
        if self._current >= self._total:
            print()


class SafeCommandRunner:
    """Run commands with robust error handling."""

    @staticmethod
    def run(command: list[str], cwd: Path | None = None) -> CommandResult:
        try:
            completed: subprocess.CompletedProcess[str] = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                check=False,
            )
            return CommandResult(
                exit_code=completed.returncode,
                stdout=completed.stdout.strip(),
                stderr=completed.stderr.strip(),
            )
        except FileNotFoundError as exc:
            return CommandResult(exit_code=127, stdout="", stderr=str(exc))
        except Exception as exc:  # noqa: BLE001
            return CommandResult(exit_code=1, stdout="", stderr=f"Execution error: {exc}")


class EnvironmentBootstrapper:
    """Create and use a dedicated virtual environment automatically."""

    def __init__(self, script_path: Path, venv_dir: Path, packages: list[str]) -> None:
        self._script_path: Path = script_path
        self._venv_dir: Path = venv_dir
        self._packages: list[str] = packages

    def ensure_reexec_in_venv(self, passthrough_args: list[str]) -> None:
        if os.environ.get("AXIOS_SCAN_VENV_ACTIVE") == "1":
            return

        if not self._venv_dir.exists():
            print(f"[step] Preparation environnement Python: creation du venv ({self._venv_dir})")
            builder = venv.EnvBuilder(with_pip=True, clear=False, symlinks=False, upgrade=False)
            builder.create(str(self._venv_dir))
        else:
            print(f"[step] Preparation environnement Python: venv deja present ({self._venv_dir})")

        python_bin: Path = self._venv_python()
        self._install_packages(python_bin)

        env: dict[str, str] = dict(os.environ)
        env["AXIOS_SCAN_VENV_ACTIVE"] = "1"
        cmd: list[str] = [str(python_bin), str(self._script_path)] + passthrough_args
        print("[step] Relance du script dans le venv pour isoler les dependances...")
        raise SystemExit(subprocess.call(cmd, env=env))

    def _venv_python(self) -> Path:
        if os.name == "nt":
            return self._venv_dir / "Scripts" / "python.exe"
        return self._venv_dir / "bin" / "python"

    def _install_packages(self, python_bin: Path) -> None:
        print("[step] Installation/maj automatique des librairies Python...")
        SafeCommandRunner.run([str(python_bin), "-m", "pip", "install", "--upgrade", "pip"])
        if self._packages:
            install_result: CommandResult = SafeCommandRunner.run(
                [str(python_bin), "-m", "pip", "install", *self._packages]
            )
            if install_result.exit_code != 0:
                print(f"[bootstrap][warning] Installation partielle: {install_result.stderr}")


class AxiosScanner:
    """Scan Node.js projects for known Axios supply-chain indicators."""

    COMPROMISED_AXIOS_VERSIONS: set[str] = {"1.14.1", "0.30.4"}
    AXIOS_LINE_PATTERN = re.compile(r"axios@([0-9]+\.[0-9]+\.[0-9]+)")
    DEFAULT_IGNORED_DIRS: set[str] = {"node_modules", ".git", ".vscode", ".idea", "AppData", ".scan-venv"}

    def __init__(self, root_path: Path) -> None:
        self._root_path: Path = root_path
        self._last_discovered_projects: list[Path] = []

    def scan(self) -> list[ProjectFinding]:
        projects: list[Path] = self._discover_projects()
        self._last_discovered_projects = projects
        print(f"[info] Analyse Axios: {len(projects)} projet(s) Node.js detecte(s).")
        if not projects:
            return []
        progress = ProgressBar("Scan des dependances npm (axios/plain-crypto-js)", len(projects))
        findings: list[ProjectFinding] = []
        for project in projects:
            findings.append(self._scan_project(project))
            progress.update()
        return findings

    def get_last_discovered_projects(self) -> list[Path]:
        return list(self._last_discovered_projects)

    def _discover_projects(self) -> list[Path]:
        discovered: list[Path] = []
        for package_json in self._root_path.rglob("package.json"):
            lowered_parts: set[str] = {part.lower() for part in package_json.parts}
            if any(name.lower() in lowered_parts for name in self.DEFAULT_IGNORED_DIRS):
                continue
            discovered.append(package_json.parent)
        return discovered

    def _scan_project(self, project_path: Path) -> ProjectFinding:
        npm_bin: str = "npm.cmd" if os.name == "nt" else "npm"
        command: list[str] = [npm_bin, "list", "axios", "plain-crypto-js", "--all", "--depth=10"]
        result: CommandResult = SafeCommandRunner.run(command, cwd=project_path)
        raw_output: str = f"{result.stdout}\n{result.stderr}"

        axios_versions: list[str] = sorted(set(self.AXIOS_LINE_PATTERN.findall(raw_output)))
        compromised: list[str] = sorted([v for v in axios_versions if v in self.COMPROMISED_AXIOS_VERSIONS])
        npm_errors: list[str] = []
        if result.exit_code not in (0, 1):
            npm_errors.append(f"npm list a retourne le code {result.exit_code}")
            if result.stderr:
                npm_errors.append(result.stderr)

        return ProjectFinding(
            project_path=str(project_path),
            axios_versions=axios_versions,
            compromised_versions_found=compromised,
            plain_crypto_js_found=("plain-crypto-js" in raw_output),
            npm_errors=npm_errors,
        )


class PlatformIoCScanner:
    """Apply simple platform-specific IoC checks."""

    IOC_PATTERN = re.compile(r"(wt\.exe|ld\.py|plain-crypto-js|axios)", re.IGNORECASE)

    def scan(self) -> dict[str, Any]:
        system_name: str = platform.system()
        if system_name == "Windows":
            return self._scan_windows()
        if system_name == "Darwin":
            return self._scan_macos()
        if system_name == "Linux":
            return self._scan_linux()
        return {"platform": system_name, "supported": False, "notes": ["OS non supporte."]}

    def _scan_windows(self) -> dict[str, Any]:
        program_data: str = os.environ.get("PROGRAMDATA", "")
        wt_path: Path = Path(program_data) / "wt.exe" if program_data else Path("C:/ProgramData/wt.exe")
        startup_dirs: list[Path] = [
            Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
            Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"),
        ]
        startup_hits, startup_scanned_count = self._scan_text_and_names(startup_dirs)
        return {
            "platform": "Windows",
            "programdata_wt_exe_found": wt_path.exists(),
            "programdata_wt_exe_path": str(wt_path),
            "suspicious_startup_entries": startup_hits,
            "startup_files_scanned_count": startup_scanned_count,
            "startup_directories_scanned": [str(path) for path in startup_dirs],
        }

    def _scan_macos(self) -> dict[str, Any]:
        paths: list[Path] = [
            Path.home() / "Library/LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        suspicious_files: list[str] = [str(p) for p in [Path("/tmp/wt"), Path("/usr/local/bin/wt")] if p.exists()]
        autostart_hits, autostart_scanned_count = self._scan_text_and_names(paths)
        return {
            "platform": "macOS",
            "suspicious_autostart_entries": autostart_hits,
            "suspicious_files_found": suspicious_files,
            "autostart_files_scanned_count": autostart_scanned_count,
            "autostart_directories_scanned": [str(path) for path in paths],
        }

    def _scan_linux(self) -> dict[str, Any]:
        paths: list[Path] = [
            Path.home() / ".config/autostart",
            Path("/etc/xdg/autostart"),
            Path("/etc/systemd/system"),
            Path.home() / ".config/systemd/user",
        ]
        suspicious_files: list[str] = [str(p) for p in [Path("/tmp/wt"), Path("/usr/local/bin/wt")] if p.exists()]
        autostart_hits, autostart_scanned_count = self._scan_text_and_names(paths)
        return {
            "platform": "Linux",
            "suspicious_autostart_entries": autostart_hits,
            "suspicious_files_found": suspicious_files,
            "autostart_files_scanned_count": autostart_scanned_count,
            "autostart_directories_scanned": [str(path) for path in paths],
        }

    def _scan_text_and_names(self, base_dirs: list[Path]) -> tuple[list[str], int]:
        matches: list[str] = []
        files_to_scan: list[Path] = []
        for base_dir in base_dirs:
            if not base_dir.exists():
                continue
            files_to_scan.extend([path for path in base_dir.rglob("*") if path.is_file()])

        if not files_to_scan:
            return matches, 0

        progress = ProgressBar("Inspection des fichiers d'autostart (IoC plateforme)", len(files_to_scan))
        for path in files_to_scan:
            progress.update()
            try:
                if self.IOC_PATTERN.search(path.name):
                    matches.append(str(path))
                    continue
                content: str = path.read_text(encoding="utf-8", errors="ignore")
                if self.IOC_PATTERN.search(content):
                    matches.append(str(path))
            except Exception:
                continue
        return sorted(set(matches)), len(files_to_scan)


class HtmlReportBuilder:
    """Render a simple, user-friendly HTML report."""

    def build(self, report: dict[str, Any]) -> str:
        verdict: dict[str, Any] = report["FinalVerdict"]
        findings: list[dict[str, Any]] = report["AxiosScan"]["projects"]
        iocs: dict[str, Any] = report["PlatformIoC"]
        analysis_summary: dict[str, Any] = report["AnalysisSummary"]

        verdict_color: str = "#0b7a2a" if verdict["Safe"] else "#b00020"
        verdict_label: str = "Aucun indicateur critique" if verdict["Safe"] else "Indicateurs suspects detectes"

        project_rows: str = "".join(self._build_project_row(item) for item in findings) or (
            "<tr><td colspan='4'>Aucun projet Node.js detecte.</td></tr>"
        )
        ioc_list: str = "".join(f"<li>{escape(str(k))}: {escape(str(v))}</li>" for k, v in iocs.items())
        analyzed_dirs_preview: list[str] = analysis_summary.get("NodeProjectsPreview", [])
        analyzed_dirs_list: str = "".join(f"<li>{escape(item)}</li>" for item in analyzed_dirs_preview) or "<li>Aucun</li>"
        omitted_count: int = int(analysis_summary.get("NodeProjectsOmittedCount", 0))
        omitted_line: str = (
            f"<p class='muted'>... et {omitted_count} repertoire(s) supplementaire(s).</p>"
            if omitted_count > 0
            else ""
        )

        return textwrap.dedent(
            f"""\
            <!doctype html>
            <html lang="fr">
            <head>
              <meta charset="utf-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1" />
              <title>Rapport securite Axios</title>
              <style>
                body {{ font-family: "Segoe UI", sans-serif; margin: 24px; background: #f5f7fb; color: #12202f; }}
                .card {{ background: white; border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; box-shadow: 0 4px 14px rgba(0,0,0,.06); }}
                .badge {{ display: inline-block; padding: 6px 10px; border-radius: 999px; color: white; background: {verdict_color}; font-weight: 600; }}
                h1, h2 {{ margin: 0 0 10px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border-bottom: 1px solid #e8edf4; padding: 8px; text-align: left; font-size: 14px; vertical-align: top; }}
                .muted {{ color: #526377; font-size: 14px; }}
                ul {{ margin: 8px 0 0 18px; }}
              </style>
            </head>
            <body>
              <div class="card">
                <h1>Rapport de securite Axios</h1>
                <p class="muted">Genere le {escape(report["Metadata"]["GeneratedAt"])} sur {escape(report["Metadata"]["Platform"])}</p>
                <span class="badge">{escape(verdict_label)}</span>
                <p><strong>Explication simple :</strong> {escape(verdict["Message"])}</p>
              </div>

              <div class="card">
                <h2>Resume</h2>
                <ul>
                  <li>Axios suspect: {escape(str(verdict["HasAxiosSuspicion"]))}</li>
                  <li>IoC plateforme suspect: {escape(str(verdict["HasPlatformIoC"]))}</li>
                  <li>Dossier scanne: {escape(report["Metadata"]["RootPath"])}</li>
                </ul>
              </div>

              <div class="card">
                <h2>Perimetre analyse (resume)</h2>
                <ul>
                  <li>Projets Node.js detectes: {escape(str(analysis_summary.get("NodeProjectsDetected", 0)))}</li>
                  <li>Projets effectivement scans: {escape(str(analysis_summary.get("NodeProjectsScanned", 0)))}</li>
                  <li>Fichiers autostart inspectes: {escape(str(analysis_summary.get("PlatformAutostartFilesScanned", 0)))}</li>
                </ul>
                <p class="muted">Apercu des repertoires Node.js analyses (limite):</p>
                <ul>{analyzed_dirs_list}</ul>
                {omitted_line}
              </div>

              <div class="card">
                <h2>Resultats par projet Node.js</h2>
                <table>
                  <thead>
                    <tr>
                      <th>Projet</th>
                      <th>Versions Axios</th>
                      <th>Versions compromises</th>
                      <th>plain-crypto-js</th>
                    </tr>
                  </thead>
                  <tbody>{project_rows}</tbody>
                </table>
              </div>

              <div class="card">
                <h2>Indicateurs plateforme ({escape(report["Metadata"]["Platform"])})</h2>
                <ul>{ioc_list}</ul>
              </div>
            </body>
            </html>
            """
        )

    def _build_project_row(self, item: dict[str, Any]) -> str:
        versions: str = ", ".join(item.get("axios_versions", [])) or "aucune"
        compromised: str = ", ".join(item.get("compromised_versions_found", [])) or "aucune"
        plain_crypto: str = "oui" if item.get("plain_crypto_js_found", False) else "non"
        return (
            "<tr>"
            f"<td>{escape(str(item.get('project_path', '')))}</td>"
            f"<td>{escape(versions)}</td>"
            f"<td>{escape(compromised)}</td>"
            f"<td>{escape(plain_crypto)}</td>"
            "</tr>"
        )


class SecurityOrchestrator:
    """Coordinate bootstrap, scan, report generation, and opening HTML output."""

    def __init__(self, root_path: Path, output_dir: Path, no_open: bool) -> None:
        self._root_path: Path = root_path
        self._output_dir: Path = output_dir
        self._no_open: bool = no_open

    def execute(self) -> int:
        print("[intro] Ce script va:")
        print("        1) verifier l'environnement Python (venv + librairies)")
        print("        2) scanner les projets Node.js pour des IoC Axios")
        print("        3) scanner les points d'autostart de l'OS")
        print("        4) generer des rapports TXT/JSON/HTML")
        self._output_dir.mkdir(parents=True, exist_ok=True)
        now: str = datetime.now().strftime("%Y%m%d-%H%M%S")
        txt_path: Path = self._output_dir / f"security-report-{now}.txt"
        json_path: Path = self._output_dir / f"security-report-{now}.json"
        html_path: Path = self._output_dir / f"security-report-{now}.html"

        print(f"[step] Scan Axios sur la racine: {self._root_path}")
        axios_scanner = AxiosScanner(self._root_path)
        project_findings: list[ProjectFinding] = axios_scanner.scan()
        discovered_projects: list[Path] = axios_scanner.get_last_discovered_projects()
        print(f"[step] Scan IoC plateforme ({platform.system()})")
        platform_ioc: dict[str, Any] = PlatformIoCScanner().scan()

        has_axios_suspicion: bool = any(item.is_suspicious for item in project_findings)
        has_platform_ioc: bool = self._has_platform_ioc(platform_ioc)
        is_safe: bool = not (has_axios_suspicion or has_platform_ioc)

        node_projects_preview_limit: int = 20
        node_projects_preview: list[str] = [str(path) for path in discovered_projects[:node_projects_preview_limit]]
        node_projects_omitted_count: int = max(len(discovered_projects) - node_projects_preview_limit, 0)
        platform_autostart_files_scanned: int = int(
            platform_ioc.get("startup_files_scanned_count", platform_ioc.get("autostart_files_scanned_count", 0))
        )

        report: dict[str, Any] = {
            "Metadata": {
                "GeneratedAt": datetime.now().isoformat(),
                "Platform": platform.system(),
                "RootPath": str(self._root_path),
                "UserName": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            },
            "AxiosScan": {"projects": [self._project_to_dict(item) for item in project_findings]},
            "PlatformIoC": platform_ioc,
            "AnalysisSummary": {
                "NodeProjectsDetected": len(discovered_projects),
                "NodeProjectsScanned": len(project_findings),
                "NodeProjectsPreview": node_projects_preview,
                "NodeProjectsOmittedCount": node_projects_omitted_count,
                "PlatformAutostartFilesScanned": platform_autostart_files_scanned,
            },
            "FinalVerdict": {
                "Safe": is_safe,
                "HasAxiosSuspicion": has_axios_suspicion,
                "HasPlatformIoC": has_platform_ioc,
                "Message": (
                    "Aucun indicateur direct Axios/IoC OS detecte."
                    if is_safe
                    else "Des indicateurs suspects ont ete trouves. Verifie rapidement les details ci-dessous."
                ),
            },
        }

        print("[step] Generation des rapports (TXT/JSON/HTML)")
        txt_path.write_text(self._build_txt(report, json_path, html_path), encoding="utf-8")
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        html_path.write_text(HtmlReportBuilder().build(report), encoding="utf-8")

        print("\n=== Rapport genere ===")
        print(f"TXT  : {txt_path}")
        print(f"JSON : {json_path}")
        print(f"HTML : {html_path}")
        print(f"\n{report['FinalVerdict']['Message']}")

        if not self._no_open:
            print("[step] Ouverture automatique du rapport HTML dans le navigateur.")
            webbrowser.open(html_path.resolve().as_uri())

        return 0 if is_safe else 2

    @staticmethod
    def _project_to_dict(project: ProjectFinding) -> dict[str, Any]:
        return {
            "project_path": project.project_path,
            "axios_versions": project.axios_versions,
            "compromised_versions_found": project.compromised_versions_found,
            "plain_crypto_js_found": project.plain_crypto_js_found,
            "npm_errors": project.npm_errors,
        }

    @staticmethod
    def _has_platform_ioc(platform_ioc: dict[str, Any]) -> bool:
        if bool(platform_ioc.get("programdata_wt_exe_found", False)):
            return True
        return bool(platform_ioc.get("suspicious_startup_entries", [])) or bool(
            platform_ioc.get("suspicious_autostart_entries", [])
        ) or bool(platform_ioc.get("suspicious_files_found", []))

    @staticmethod
    def _build_txt(report: dict[str, Any], json_path: Path, html_path: Path) -> str:
        verdict: dict[str, Any] = report["FinalVerdict"]
        summary: dict[str, Any] = report["AnalysisSummary"]
        lines: list[str] = [
            "Security check report",
            f"Generated at: {report['Metadata']['GeneratedAt']}",
            f"Platform: {report['Metadata']['Platform']}",
            f"User: {report['Metadata']['UserName']}",
            f"RootPath: {report['Metadata']['RootPath']}",
            "",
            f"Final verdict: {verdict['Message']}",
            f"Flags: AxiosSuspicion={verdict['HasAxiosSuspicion']}, PlatformIoC={verdict['HasPlatformIoC']}",
            "",
            "Analysis summary:",
            f"- Node projects detected: {summary['NodeProjectsDetected']}",
            f"- Node projects scanned: {summary['NodeProjectsScanned']}",
            f"- Platform autostart files scanned: {summary['PlatformAutostartFilesScanned']}",
            f"- Node projects preview (limited): {len(summary['NodeProjectsPreview'])}",
            f"- Additional projects omitted from preview: {summary['NodeProjectsOmittedCount']}",
            "",
            f"JSON report: {json_path}",
            f"HTML report: {html_path}",
        ]
        return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan Axios tout-en-un avec venv auto, installation libs et rapport HTML."
    )
    parser.add_argument("--root", type=Path, default=Path.home(), help="Dossier racine a scanner.")
    parser.add_argument("--output-dir", type=Path, default=Path("./reports"), help="Dossier des rapports.")
    parser.add_argument("--venv-dir", type=Path, default=Path("./.scan-venv"), help="Dossier du venv automatique.")
    parser.add_argument("--no-open", action="store_true", help="N'ouvre pas la page HTML a la fin.")
    return parser.parse_args()


def main() -> None:
    args: argparse.Namespace = parse_args()
    bootstrapper = EnvironmentBootstrapper(
        script_path=Path(__file__).resolve(),
        venv_dir=args.venv_dir,
        packages=["jinja2"],
    )
    passthrough_args: list[str] = sys.argv[1:]
    bootstrapper.ensure_reexec_in_venv(passthrough_args)

    exit_code: int = SecurityOrchestrator(
        root_path=args.root,
        output_dir=args.output_dir,
        no_open=args.no_open,
    ).execute()
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

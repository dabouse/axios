from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


@dataclass(frozen=True)
class ProjectFinding:
    """Represent one scanned Node.js project and its security findings."""

    project_path: str
    axios_versions: list[str]
    compromised_versions_found: list[str]
    plain_crypto_js_found: bool
    npm_errors: list[str]

    @property
    def is_suspicious(self) -> bool:
        return bool(self.compromised_versions_found or self.plain_crypto_js_found)


class AxiosSupplyChainScanner:
    """Centralize scanning logic to keep checks reusable and testable."""

    COMPROMISED_AXIOS_VERSIONS: set[str] = {"1.14.1", "0.30.4"}
    AXIOS_LINE_PATTERN = re.compile(r"axios@([0-9]+\.[0-9]+\.[0-9]+)")
    DEFAULT_IGNORED_DIRS: set[str] = {
        "node_modules",
        ".git",
        ".vscode",
        ".idea",
        "AppData",
    }

    def __init__(self, root_path: Path, ignored_dirs: set[str] | None = None) -> None:
        self._root_path: Path = root_path
        self._ignored_dirs: set[str] = ignored_dirs or self.DEFAULT_IGNORED_DIRS

    def discover_node_projects(self) -> list[Path]:
        projects: list[Path] = []
        for path in self._root_path.rglob("package.json"):
            if self._is_ignored(path):
                continue
            projects.append(path.parent)
        return projects

    def scan_project(self, project_path: Path) -> ProjectFinding:
        npm_output, npm_errors = self._run_npm_list(project_path)
        axios_versions: list[str] = sorted(set(self.AXIOS_LINE_PATTERN.findall(npm_output)))
        compromised_versions: list[str] = sorted(
            version for version in axios_versions if version in self.COMPROMISED_AXIOS_VERSIONS
        )
        plain_crypto_js_found: bool = "plain-crypto-js" in npm_output

        return ProjectFinding(
            project_path=str(project_path),
            axios_versions=axios_versions,
            compromised_versions_found=compromised_versions,
            plain_crypto_js_found=plain_crypto_js_found,
            npm_errors=npm_errors,
        )

    def check_windows_iocs(self) -> dict[str, bool]:
        program_data: str | None = None
        try:
            import os

            program_data = os.environ.get("PROGRAMDATA")
        except Exception:
            program_data = None

        if not program_data:
            return {"programdata_wt_exe_found": False}

        suspicious_file: Path = Path(program_data) / "wt.exe"
        return {"programdata_wt_exe_found": suspicious_file.exists()}

    def _is_ignored(self, package_json_path: Path) -> bool:
        lowered_parts: set[str] = {part.lower() for part in package_json_path.parts}
        return any(ignored.lower() in lowered_parts for ignored in self._ignored_dirs)

    def _run_npm_list(self, project_path: Path) -> tuple[str, list[str]]:
        npm_candidates: list[str] = ["npm.cmd", "npm"] if os.name == "nt" else ["npm"]

        last_file_not_found: FileNotFoundError | None = None
        for npm_bin in npm_candidates:
            try:
                result: subprocess.CompletedProcess[str] = subprocess.run(
                    [npm_bin, "list", "axios", "plain-crypto-js", "--all", "--depth=10"],
                    cwd=project_path,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                combined: str = f"{result.stdout}\n{result.stderr}".strip()
                errors: list[str] = []
                if result.returncode not in (0, 1):
                    errors.append(f"npm list a retourne le code {result.returncode}")
                return combined, errors
            except FileNotFoundError as exc:
                last_file_not_found = exc
                continue

        try:
            if last_file_not_found is not None:
                return "", ["npm introuvable. Verifie npm.cmd/npm dans le PATH pour Python."]
            return "", ["npm introuvable. Verifie Node.js/npm."]
        except Exception as exc:
            return "", [f"Erreur lors de l'execution npm: {exc}"]


class ScanReporter:
    """Format output clearly for humans and automation."""

    @staticmethod
    def print_human_report(
        root_path: Path,
        findings: Sequence[ProjectFinding],
        windows_iocs: dict[str, bool],
    ) -> None:
        print(f"Racine analysee: {root_path}")
        print(f"Nombre de projets Node.js detectes: {len(findings)}\n")

        suspicious_count: int = 0
        for finding in findings:
            if finding.is_suspicious:
                suspicious_count += 1
            ScanReporter._print_project_block(finding)

        print("=== Indicateurs systeme (Windows) ===")
        wt_state: str = "PRESENT" if windows_iocs.get("programdata_wt_exe_found", False) else "absent"
        print(f"%PROGRAMDATA%\\wt.exe : {wt_state}\n")

        if suspicious_count == 0 and not windows_iocs.get("programdata_wt_exe_found", False):
            print("Aucun indicateur direct de compromission detecte dans cette analyse.")
        else:
            print("Attention: indicateur(s) suspect(s) detecte(s).")
            print("Isole la machine du reseau et lance une reponse a incident complete.")

    @staticmethod
    def print_json_report(findings: Sequence[ProjectFinding], windows_iocs: dict[str, bool]) -> None:
        payload: dict[str, object] = {
            "projects": [asdict(item) for item in findings],
            "windows_iocs": windows_iocs,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))

    @staticmethod
    def _print_project_block(finding: ProjectFinding) -> None:
        print(f"--- Projet: {finding.project_path} ---")
        if finding.axios_versions:
            print(f"Axios detecte: {', '.join(finding.axios_versions)}")
        else:
            print("Axios detecte: aucun")

        if finding.compromised_versions_found:
            print(f"Versions compromises detectees: {', '.join(finding.compromised_versions_found)}")
        else:
            print("Versions compromises detectees: aucune")

        print(f"Dependance plain-crypto-js detectee: {'oui' if finding.plain_crypto_js_found else 'non'}")
        if finding.npm_errors:
            print(f"Erreurs npm: {' | '.join(finding.npm_errors)}")
        print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanner de compromission Axios (versions 1.14.1 / 0.30.4 et IoC associes)."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home(),
        help="Dossier racine a scanner (defaut: dossier utilisateur).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Affiche le rapport au format JSON.",
    )
    return parser.parse_args()


def run_scan(root_path: Path, output_json: bool) -> int:
    scanner = AxiosSupplyChainScanner(root_path=root_path)
    projects: list[Path] = scanner.discover_node_projects()
    findings: list[ProjectFinding] = [scanner.scan_project(project_path=project) for project in projects]
    windows_iocs: dict[str, bool] = scanner.check_windows_iocs()

    if output_json:
        ScanReporter.print_json_report(findings=findings, windows_iocs=windows_iocs)
    else:
        ScanReporter.print_human_report(root_path=root_path, findings=findings, windows_iocs=windows_iocs)

    suspicious: bool = any(item.is_suspicious for item in findings) or windows_iocs.get(
        "programdata_wt_exe_found", False
    )
    return 2 if suspicious else 0


def main() -> None:
    args = parse_args()
    exit_code: int = run_scan(root_path=args.root, output_json=args.json)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
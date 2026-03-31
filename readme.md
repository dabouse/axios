# Scanner de compromission Axios

Utilise **un seul script**: `security-all-in-one.py`.

Ce script fonctionne sur Windows, macOS et Linux, et fait:

- creation/usage automatique d'un venv (`.scan-venv`)
- installation automatique des dependances Python
- scan Axios (`1.14.1` / `0.30.4`) + `plain-crypto-js`
- scan IoC plateforme (autostart, fichiers suspects)
- generation des rapports `txt`, `json` et `html`
- ouverture automatique du rapport HTML

## Utilisation (simple)

### Windows

```powershell
python .\security-all-in-one.py --root "$env:USERPROFILE"
```

### macOS / Linux

```bash
python3 ./security-all-in-one.py --root "$HOME"
```

### Mode sans ouverture navigateur

```bash
python3 ./security-all-in-one.py --root "$HOME" --no-open
```

## Rapports

Les rapports sont generes dans `reports/`:

- `security-report-YYYYMMDD-HHMMSS.txt`
- `security-report-YYYYMMDD-HHMMSS.json`
- `security-report-YYYYMMDD-HHMMSS.html`

Le rapport contient:

- le verdict final
- un resume plateforme
- le detail des trouvailles par projet

## Publication GitHub

Le fichier `.gitignore` est deja configure pour ignorer:

- venv (`.scan-venv`, `.venv`, `venv`, `env`)
- rapports (`reports/`, `*.html`, `*.json`, `*.txt`)
- fichiers cache Python et fichiers IDE/OS
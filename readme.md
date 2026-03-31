# Scanner de compromission Axios

Utilise **un seul script**: `security-all-in-one.py`.

Ce script fonctionne sur Windows, macOS et Linux, et fait:

- creation/usage automatique d'un venv (`.scan-venv`)
- installation automatique des dependances Python
- scan Axios (`1.14.1` / `0.30.4`) + `plain-crypto-js`
- scan IoC plateforme (autostart, fichiers suspects)
- generation des rapports `txt`, `json` et `html`
- ouverture automatique du rapport HTML

## Pourquoi ce fichier existe

Ce fichier a ete cree pour avoir une procedure **simple, reproductible et portable** apres un incident de securite:

- un seul point d'entree (`security-all-in-one.py`) au lieu de plusieurs commandes manuelles
- meme methode sur Windows, macOS et Linux
- execution standardisee (venv auto + dependances auto)
- rapports horodates pour garder une trace exploitable (support, audit, Git)
- sortie lisible pour un non-specialiste via la page HTML

L'objectif principal est de reduire les erreurs humaines pendant un controle de compromission.

## Faille supply-chain Axios (explication simple)

Une faille supply-chain signifie que le risque ne vient pas directement de ton code, mais de la **chaine de dependances** (registry, package, version, transitif).

Dans le contexte de ce scanner, on cherche des indicateurs lies a un incident Axios:

- versions Axios signalees comme suspectes dans ce protocole (`1.14.1` et `0.30.4`)
- presence de `plain-crypto-js` (dependance associee a des comportements suspects selon ce scenario)
- indices de persistance sur la machine (autostart/fichiers suspects)

Pourquoi c'est dangereux:

- un package compromis peut executer du code malveillant lors de l'installation ou a l'execution
- ce code peut voler des secrets (tokens, cles API, credentials) ou installer une persistance
- l'infection peut toucher plusieurs projets via des dependances transitives

Limite importante: ce script detecte des **indicateurs** de compromission, pas une preuve absolue d'absence de risque.

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
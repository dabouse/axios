# Scanner de compromission Axios

Ce script Python analyse des projets Node.js pour identifier des indicateurs lies a l'attaque supply chain Axios (versions `1.14.1` et `0.30.4`) ainsi que la presence de `plain-crypto-js`.

## Ce que fait le script

- Recherche recursive des projets Node.js via `package.json`.
- Ignore les dossiers lourds/non pertinents (`node_modules`, `.git`, `.vscode`, `.idea`, `AppData`).
- Execute `npm list axios plain-crypto-js --all --depth=10` dans chaque projet.
- Detecte explicitement les versions compromises d'Axios.
- Verifie un IoC Windows simple: `%PROGRAMDATA%\wt.exe`.
- Exporte un rapport lisible ou JSON.

## Prerequis

- Python 3.10+
- Node.js + npm disponibles dans le `PATH`
- Sous Windows, verifier aussi que `npm.cmd` est disponible pour les sous-processus Python

## Utilisation

### Analyse du dossier utilisateur (par defaut)

```powershell
python .\axios1.py
```

### Analyse d'un dossier cible

```powershell
python .\axios1.py --root "C:\Users\damie"
```

### Sortie JSON

```powershell
python .\axios1.py --root "C:\Users\damie" --json
```

## Script unique pour un autre PC

Si tu veux rejouer automatiquement presque tout le protocole sur une autre machine Windows, utilise `security-check-all.ps1`.

### Ce script fait automatiquement

- verification Node/npm
- mise a jour npm optionnelle
- scan Axios supply-chain via `axios1.py` (JSON)
- controles IoC Windows simples (fichier `%PROGRAMDATA%\wt.exe`, Startup, Run keys)
- quick scan Microsoft Defender (optionnel)
- generation d'un rapport texte + JSON

### Commandes recommandees

Depuis ce dossier:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\security-check-all.ps1 -RootPath "$env:USERPROFILE" -UpdateNpm
```

Si tu veux ignorer Defender (ex: machine verrouillee):

```powershell
.\security-check-all.ps1 -RootPath "$env:USERPROFILE" -UpdateNpm -SkipDefender
```

## Version cross-platform (Windows/macOS/Linux)

Pour une version unique qui fonctionne aussi sur macOS et Linux, utilise `security-check-all.py`.

### Ce script fait automatiquement

- scan Axios supply-chain via `axios1.py` (JSON)
- controle IoC adapte a la plateforme:
  - Windows: `%PROGRAMDATA%\wt.exe` + Startup basique
  - macOS: LaunchAgents/LaunchDaemons + chemins suspects (`/tmp/wt`, `/usr/local/bin/wt`, `~/.local/bin/wt`)
  - Linux: autostart/systemd user + chemins suspects (`/tmp/wt`, `/usr/local/bin/wt`, `~/.local/bin/wt`)
- generation d'un rapport texte + JSON
- separation du verdict principal Axios/IoC et de la note securite systeme

### Commandes recommandees

#### Windows (PowerShell)

```powershell
python .\security-check-all.py --root "$env:USERPROFILE"
```

#### macOS / Linux

```bash
python3 ./security-check-all.py --root "$HOME"
```

#### Scan cible du dossier courant

```bash
python3 ./security-check-all.py --root "."
```

## Version tout-en-un (venv + libs + HTML)

Si tu veux tout lancer avec un seul fichier autonome, utilise `security-all-in-one.py`.

### Ce que fait ce script

- cree automatiquement un environnement virtuel local (`.scan-venv`)
- installe automatiquement les librairies Python requises
- lance le scan Axios + IoC plateforme (Windows/macOS/Linux)
- explique clairement chaque etape dans la console (`[intro]`, `[step]`, `[info]`)
- affiche une barre de progression pour les etapes longues (scan npm et inspection autostart)
- genere 3 rapports:
  - `txt`
  - `json`
  - `html`
- ajoute un resume du perimetre analyse (nombre de projets detectes/scannes, volume de fichiers autostart inspectes, apercu limite des repertoires)
- ouvre automatiquement la page HTML en fin de scan pour une lecture simple

### Commandes

#### Windows (PowerShell)

```powershell
python .\security-all-in-one.py --root "$env:USERPROFILE"
```

#### macOS / Linux

```bash
python3 ./security-all-in-one.py --root "$HOME"
```

#### Ne pas ouvrir le navigateur (mode CI/serveur)

```bash
python3 ./security-all-in-one.py --root "$HOME" --no-open
```

## Publication GitHub

Un fichier `.gitignore` est fourni pour eviter de publier des artefacts locaux:

- environnements virtuels (`.scan-venv`, `.venv`, `venv`, `env`)
- rapports de scan generes (`reports/`, `*.html`, `*.json`, `*.txt`)
- fichiers cache/build Python
- dossiers IDE/systeme (`.vscode`, `.idea`, `.DS_Store`, `Thumbs.db`)

Si tu veux versionner un rapport ponctuel, retire temporairement la regle concernee dans `.gitignore`.

### Sorties

Le script cree des rapports dans `.\reports\`:

- `security-report-YYYYMMDD-HHMMSS.txt`
- `security-report-YYYYMMDD-HHMMSS.json`

Le JSON contient des sections distinctes:

- `FinalVerdict`: verdict principal base uniquement sur les IoC Axios/Windows actuels.
- `DefenderAssessment`: statut informatif de l'historique Defender.

Tu peux commit `axios1.py`, `security-check-all.ps1` et `readme.md` dans Git, puis lancer la meme procedure sur ton autre ordinateur.

## Interpretation

- **FinalVerdict = Safe true**: aucun IoC Axios/Windows direct detecte.
- **FinalVerdict = Safe false**: IoC Axios/Windows detecte:
  - version Axios compromise (`1.14.1` ou `0.30.4`)
  - presence de `plain-crypto-js`
  - presence de `%PROGRAMDATA%\wt.exe`
- **DefenderAssessment.HasThreatHistory = true**: historique Defender non vide. Ce signal est informatif et n'invalide pas a lui seul le verdict Axios/Windows.

Dans ce cas, traite la machine comme potentiellement compromise:

1. isole immediatement la machine du reseau;
2. revoque/renouvelle tous les secrets (tokens, cles API, cles SSH, mots de passe);
3. effectue une reinstallation propre ou une restauration depuis une sauvegarde saine.

## Limites

- Un attaquant peut supprimer ou masquer des traces.
- L'absence de preuve dans `npm list` ne vaut pas preuve d'absence d'infection.
- Pour un audit complet, ajoute des controles EDR/AV, analyse des processus, et forensique systeme.

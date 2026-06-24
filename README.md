# OCP Network Automation

Application Python d'automatisation des opérations réseau — OCP Jorf Lasfar (350+ switches Cisco)

---

## Progression du projet

### v0.1 — 24 juin 2026 — Connexion SSH de base
Premier script Python capable de se connecter à un équipement Cisco via SSH et récupérer son hostname.

![v0.1](docs/screenshots/screenshot_v01.png)

### v0.2 — 24 juin 2026 — Connexion multi-équipements
Connexion simultanée à R1, R2 et R3 — récupération du hostname de chaque équipement.

![v0.2 CMD](docs/screenshots/screenshot_v02_cmd.png)
![v0.2 GNS3](docs/screenshots/screenshot_v02_gns3.png)

### v0.3 — 24 juin 2026 — Envoi de configuration groupée
Envoi de commandes de configuration sur R1, R2 et R3 simultanément via SSH.
Vérification appliquée directement sur les équipements.

![v0.3 CMD](docs/screenshots/screenshot_v03_cmd.png)
![v0.3 GNS3](docs/screenshots/screenshot_v03_gns3.png)

---

## Installation

```bash
pip install -r requirements.txt
```

## Lancer l'application

```bash
python main.py
```
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

### v0.4 — 25 juin 2026 — Chargement des équipements depuis Excel
Import automatique de la liste des équipements depuis un fichier Excel (devices.xlsx).
Plus besoin de modifier le code pour ajouter un équipement.

![v0.4 CMD](docs/screenshots/screenshot_v04_cmd.png)
![v0.4 Excel](docs/screenshots/screenshot_v04_excel.png)

### v0.5 — 25 juin 2026 — Sauvegarde automatique des configurations
Sauvegarde automatique de la running-config de chaque équipement dans des fichiers horodatés.

![v0.5 CMD](docs/screenshots/screenshot_v05_cmd.png)
![v0.5 Files](docs/screenshots/screenshot_v05_files.png)

### v0.6 — 25 juin 2026 — Première interface graphique
Première version GUI avec Tkinter — boutons Envoyer Config et Sauvegarder avec log en temps réel.
Logo OCP intégré dans la barre de titre.

![v0.6](docs/screenshots/screenshot_v06.png)

### v0.7 — 25 juin 2026 — Interface modernisée avec CustomTkinter
Interface repensée avec CustomTkinter — thème sombre, onglets Envoi Config et Sauvegarde.
Traitement en arrière-plan pour éviter le gel de l'interface dans les ancienne version.

![v0.7 Config](docs/screenshots/screenshot_v07_config.png)
![v0.7 Backup](docs/screenshots/screenshot_v07_backup.png)

### v0.8 — 26 juin 2026 — Ajout onglet Scanner Réseau
Scan de sous-réseau en parallèle (50 threads) — détecte tous les hôtes actifs en temps réel.
Utile pour vérifier quels équipements sont en ligne avant de pousser une configuration.

![v0.8 Scanner](docs/screenshots/screenshot_v08_scanner.png)

### v0.9 — 1 juillet 2026 — Test sur switch Cisco réel + améliorations UI
Premier test réussi sur un vrai switch Cisco Catalyst 3750 (WS-C3750V2-24TS) en environnement LAN.
- Ajout mode clair/sombre avec mémorisation
- Historique des scans cliquable
- Détection du type d'équipement (SSH/Telnet/RDP)
- Labels descriptifs sur chaque onglet

![v0.9 Config](docs/screenshots/screenshot_v09_config.png)
![v0.9 Backup](docs/screenshots/screenshot_v09_backup.png)
![v0.9 Scanner](docs/screenshots/screenshot_v09_scanner.png)

### v1.0 — 2 juillet 2026 — Zone de texte + chargement de fichier de commandes

Ajout d'une interface plus flexible pour l'envoi de configuration : possibilité de
taper les commandes directement dans l'application ou de charger un fichier .txt
existant, sans devoir passer uniquement par `commands.txt`.

- Zone de texte editable pour taper les commandes directement dans l'UI
- Bouton "Parcourir .txt" pour charger un fichier de commandes existant
- Priorite automatique : zone de texte > commands.txt si la zone est vide
- Fenetre redimensionnable avec taille minimale (UI ne casse plus en dessous d'une certaine taille)
- Teste et valide sur switch Cisco Catalyst 3750 reel (site Jorf Lasfar) :
  push de `service timestamps debug datetime msec localtime`, confirme via
  `show running-config | include service timestamps` en SSH direct

![v1.0 Config](docs/screenshots/screenshot_v10_config.png)
![v1.0 Backup](docs/screenshots/screenshot_v10_backup.png)

### v1.1 — 3 juillet 2026 — Corrections UX + détection d'erreurs + zoom

Corrections de bugs identifies lors des tests sur switch reel, et ajout de
controles pour rendre l'envoi de configuration plus sur.

- Bouton d'arret en cours d'envoi ("Arreter l'envoi") : empeche les clics multiples
  qui melangeaient le log de resultat
- Fix du glitch visuel au changement de theme dark/light
- Detection des commandes rejetees par le switch (`% Invalid input`, `% Incomplete
  command`, etc.) au lieu d'un faux message de succes
- Controles de zoom (+/-) : le contenu devient scrollable a tout niveau de zoom,
  la fenetre elle-meme ne change jamais de taille
- Correction du bouton de suppression dans l'historique du scanner, invisible en mode clair

![v1.1 Arret en cours](docs/screenshots/screenshot_v11_stop_button.png)
![v1.1 Detection erreur](docs/screenshots/screenshot_v11_error_detection.png)
![v1.1 Zoom](docs/screenshots/screenshot_v11_zoom.png)

### v1.2 — 8 juillet 2026 — Scan reseau professionnel avec Nmap

Remplacement du scan basique (ping + test de 5 ports en dur) par un vrai scan
Nmap (python-nmap), avec detection de versions de services et d'OS.

- Detection des versions de services (ex: "HTTP: Huawei router http admin")
  au lieu de juste "port ouvert"
- Detection d'OS avec pourcentage de confiance (ex: "Linux 3.18.24 (96%)")
- Champ "Ports" configurable (syntaxe Nmap : liste ou plage), 9 ports par
  defaut adaptes a un contexte reseau/IT (SSH, Telnet, HTTP, NETCONF, etc.),
  avec un bouton "Tous les ports" (1-65535)
- Scan toujours en -Pn (aucune decouverte d'hote) : ne rate jamais un hote qui
  repond au ping mais est ignore par la decouverte Nmap standard (ex routeur
  GNS3), sans surcout de temps mesurable (verifie via benchmark_scan.py)
- Deux objectifs distincts : le TCP (champ "Ports") sert a l'INVENTAIRE reseau
  (appareils + services), l'UDP sert a la RECHERCHE DE VULNERABILITES sur les
  services UDP les plus a risque — pas a un inventaire de ports exhaustif
- Option "Inclure UDP (-sU)" : scanne les 100 ports UDP les plus COURANTS (approche
  "top ports" de Nmap, basee sur les frequences reelles du fichier nmap-services —
  meilleure couverture qu'une liste figee), en union avec les ports vuln curatee
  (SNMP, TFTP, DNS, NTP, DHCP, ISAKMP, SSDP) toujours inclus. Independant du champ
  "Ports" (qui ne concerne que le TCP). Des scripts NSE de detection (snmp-info,
  tftp-enum, dns-recursion, ntp-monlist, ike-version, upnp-info...) se declenchent
  sur leurs services respectifs quel que soit le port. Les vulnerabilites potentielles
  sont listees dans les logs et signalees dans le detail de l'hote (flag "⚠ Vuln: ...").
  Nombre de ports configurable (TOP_UDP_PORTS_COUNT). NB : --top-ports ne pouvant pas
  coexister avec -p dans une meme invocation Nmap, la liste UDP est calculee depuis
  nmap-services et combinee au TCP via "T:<ports>,U:<top-udp>"
- Timeout par hote (--host-timeout) dynamique, modele cout-fixe + cout-marginal
  calibre sur mesures reelles : 30s pour les ports par defaut, ~5-6 min pour un
  scan 1-65535 TCP, ~8 min pour 1-65535 TCP + UDP(100) + OS. Le cout UDP reste
  borne (nombre de ports "top" + cout des scripts), plus jamais de timeout a rallonge
- Detection d'OS (-O) activee seulement si l'app tourne en administrateur :
  detectee AVANT le scan, ce qui evite la tentative -O vouee a l'echec suivie
  d'un second scan complet de repli (qui doublait le temps)
- Hotes coupes par le timeout signales explicitement dans les logs (au lieu de
  disparaitre en silence et de laisser croire a une absence d'hote)
- Bouton "Nouvelle fenetre de scan" : ouvre une fenetre independante (avec le
  logo OCP) pour lancer PLUSIEURS scans en parallele (ex : plusieurs sous-reseaux
  a la fois). Chaque fenetre gere son propre scan de A a Z (champs, log, thread,
  annulation) sans etat partage ; fermer une fenetre annule proprement son scan
  (arret du sous-processus nmap.exe). L'historique reste commun a toutes les fenetres.
  La fenetre s'ouvre au premier plan avec le focus, et ses libelles reviennent a la
  ligne (responsive) quand elle est etroite
- Bouton de sauvegarde protege contre les clics multiples (meme mecanisme que
  l'envoi de config) : "Arreter la sauvegarde" pendant l'execution, plus de
  sauvegardes lancees en parallele par des clics repetes
- Repli automatique sur le scan basique si Nmap/python-nmap est absent, avec
  message clair a l'utilisateur
- Bouton "Arreter le scan" : interruption reelle et immediate du scan Nmap en
  cours (pas juste a la fin), via arret direct du sous-processus
- Demarrage de l'application accelere (imports lourds charges a la demande
  plutot qu'au lancement)
- Temps total du scan affiche a la fin, pour comparaison

Teste sur reseau domestique reel : 7 hotes detectes sur un /24, avec
identification correcte du routeur (Huawei, Linux embarque, 96% de confiance).

![v1.2 Scan Nmap](docs/screenshots/screenshot_v12_scan.png)
![v1.2 Arret scan](docs/screenshots/screenshot_v12_stop.png)

### v1.3 — 13 juillet 2026 — Reporting CSV

Generation automatique d'un rapport CSV recapitulatif apres chaque operation
(push config, backup, scan reseau), exploitable directement dans Excel.

- Un fichier horodate par execution (reports/config_..., backup_..., scan_...)
- Une ligne par appareil/resultat : date, appareil, operation, statut, detail
- Encodage UTF-8 avec BOM pour un affichage correct des accents dans Excel
- Rapport non genere si l'operation n'a produit aucune ligne (pas de fichier vide)
- Chemin du rapport affiche dans le log de l'app a la fin de chaque operation

Teste en conditions reelles sur le reseau OCP (Jorf Lasfar) : rapports de
config (Sw1/R2/R3) et de scan (192.168.56.0/24) generes et verifies.

![v1.3 Rapport config](docs/screenshots/screenshot_v13_report.png)
![v1.3 Rapport scan](docs/screenshots/screenshot_v13_report2.png)

### v1.4-1.5 — 14-15 juillet 2026 — Scan complet, fenetres multiples, UDP cible sur vulnerabilites

**v1.4 — Scan complet et fenetres de scan multiples**
- Decouverte toujours en -Pn (case a cocher supprimee, aucun gain de vitesse mesure)
- Bouton "Tous les ports" (1-65535) + timeout calcule dynamiquement selon le
  nombre de ports et la detection d'OS
- Plusieurs scans en parallele dans des fenetres separees independantes (bouton
  "Nouvelle fenetre de scan"), chacune avec son propre thread et son propre
  rapport CSV
- Bouton de sauvegarde desormais protege contre les clics multiples (meme
  pattern que config/scan)

**v1.5 — UDP redefini comme recherche de vulnerabilites ciblee**
- Le scan UDP ne scanne plus une plage de ports (impraticable, notamment contre
  Windows) mais les 100 ports UDP les plus courants (donnees Nmap) + 8 ports a
  haut risque (SNMP, TFTP, DNS, NTP, DHCP, ISAKMP, SSDP), avec des scripts NSE
  de detection de vulnerabilites
- Les vulnerabilites potentielles detectees sont signalees clairement dans le
  log et incluses dans le rapport CSV

Teste sur le reseau OCP (Jorf Lasfar) : scan complet TCP + OS sur 2 hotes
reussi en 366.6s sans timeout ; detection de vulnerabilite reelle validee sur
Sw1 (service NTP non synchronise, stratum 16) et sur un PC Windows (en-tete
serveur HTTP expose).

![v1.4 Bouton de sauvegarde](docs/screenshots/screenshot_v14_Bouton_de_sauvegarde.png)
![v1.4 Fenetres multiples](docs/screenshots/screenshot_v14_multi_window.png)
![v1.5 Detection vuln](docs/screenshots/screenshot_v15_vuln.png)
![v1.5 Scan complet](docs/screenshots/screenshot_v15_Scan.png)

### v1.6 — 29 juillet 2026 — Laboratoire d'infrastructure GNS3 complet (20 jours de travail)

Jusqu'ici, l'application avait ete testee sur un nombre limite d'equipements
(Sw1, R2/R3, un switch Catalyst reel isole). Les 20 derniers jours ont ete
consacres a construire, dans GNS3, un laboratoire complet et realiste :
plusieurs sites relies par un vrai routage, un firewall reel avec une DMZ,
des serveurs reels rendant de vrais services, et un acces SSH verifie sur
l'ensemble des equipements. Ce travail ne touche pas au code de
l'application elle-meme, mais fournit desormais un environnement de test
bien plus proche d'un vrai reseau d'entreprise que les quelques appareils
isoles utilises jusqu'a v1.5.

**Topologie reseau (siege + 2 succursales)**

- Modele hierarchique a 3 niveaux : Core (CORE-HQ) → Distribution (DIST-HQ1,
  DIST-HQ2, DIST-BR1, DIST-BR2) → Acces (ACC-SW-HQ1 + postes/serveurs)
- OSPF (aire 0) sur l'ensemble du reseau, y compris les liens WAN vers les
  2 succursales — toutes les adjacences verifiees FULL
- Lien redondant DIST-HQ1 ↔ DIST-HQ2 : le siege reste operationnel meme si
  CORE-HQ tombe en panne
- 6 departements repartis sur 3 sites (IT, RH, Finance, Commercial,
  Direction, Production, Logistique)

**Serveurs reels, un par departement**

Chaque serveur ci-dessous n'est pas une simulation : c'est une vraie machine
Alpine Linux installee sur disque virtuel (pas juste demarree depuis l'ISO),
faisant tourner un vrai logiciel de serveur, verifie fonctionnel — y compris
apres redemarrage de la machine.

- **SRV-WEB** (Dept IT, place en DMZ) — Apache 2.4, sert une vraie page HTML,
  accessible depuis l'exterieur du reseau sur le port 80 uniquement (voir
  section Securite ci-dessous)
- **SRV-FTP** (Dept RH) — OpenSSH avec SFTP, compte `ftpuser` dedie, acces
  fichiers securise par SSH plutot que du FTP en clair
- **SRV-DNS** (Dept Finance) — dnsmasq, resout de vrais noms de domaine
  internes (`srv-web.ocp-lab.local`, etc.) vers les IP du laboratoire
- **SRV-INTRANET** (Succursale 1, Dept Commercial) — nginx, sert une page
  intranet
- **SRV-SYSLOG** (Succursale 2, Dept Production) — rsyslog, ecoute et
  reçoit de vrais messages syslog distants (UDP/TCP port 514), verifie avec
  un message de test recu et correctement horodate/classe

**Securite perimetrique**

- Pare-feu reel (Shorewall, sur Alpine Linux) avec politique de zones
  net/loc/dmz et refus par defaut (default-deny)
- DMZ fonctionnelle : SRV-WEB est isole sur sa propre interface reseau
  dediee du pare-feu, avec une seule regle explicite autorisant le port 80
  depuis l'exterieur — tout le reste reste bloque
- Un poste "client externe" dedie (EXT-CLIENT), place hors du pare-feu,
  demontre concretement le comportement reel : acces au port 80 de SRV-WEB
  reussi, ping vers le reseau interne bloque, tentative de connexion SSH
  vers SRV-WEB bloquee — les 3 tests verifies dans une seule session
- Une ACL departementale demontre la segmentation de securite au niveau
  routeur (pas seulement les VLAN) : le departement Finance ne peut pas
  acceder au serveur FTP du departement RH, alors que l'acces Internet et
  l'acces depuis les autres departements restent fonctionnels — teste dans
  les deux sens pour confirmer que la regle est precise et non un blocage
  general

**Acces administrateur reel**

- Un hote relais (jump host) Alpine Linux, avec adressage NAT et
  redirection de routes, permet a un vrai poste Windows d'acceder au
  laboratoire — le meme chemin que celui qu'empruntera l'application en
  conditions reelles
- SSH configure et verifie sur les 7 routeurs et le switch d'acces
  (authentification locale, cles RSA, `transport input ssh` — telnet
  desactive), avec adressage de boucle de loopback prive (`10.255.255.0/24`)

**Difficultes rencontrees et comment elles ont ete resolues**

- *Adresses IP en conflit avec de vraies adresses Internet* — les premieres
  boucles de loopback des routeurs (1.1.1.1, etc.) coincidaient avec de
  vraies adresses publiques existantes (ex. le DNS public de Cloudflare).
  Resultat : certains tests de connectivite semblaient reussir alors qu'ils
  contactaient en realite un vrai serveur sur Internet, pas le routeur du
  laboratoire. Corrige en renumerotant toutes les boucles de loopback dans
  une plage strictement privee (`10.255.255.0/24`).
- *Blocage de gros paquets (MTU/fragmentation)* — les telechargements de
  paquets et certaines connexions plus lourdes echouaient silencieusement
  sur les chemins reseau les plus longs (plusieurs sauts de routeurs),
  alors que les simples ping fonctionnaient. Diagnostique comme un probleme
  classique de MTU/PMTU sur un reseau multi-sauts ; corrige en activant
  `CLAMPMSS=Yes` sur le pare-feu, qui ajuste automatiquement la taille des
  paquets TCP a la taille maximale supportee par le chemin.
- *Machines virtuelles perdant leur configuration a chaque redemarrage* —
  le probleme le plus long a resoudre. Plusieurs machines Alpine (le jump
  host, le pare-feu, les serveurs) demarraient en mode "live" depuis leur
  CD d'installation plutot que d'etre reellement installees sur un disque
  virtuel : tout fonctionnait parfaitement tant que la machine restait
  allumee, mais un redemarrage effaçait entierement la configuration.
  Resolu en installant proprement chaque machine sur son propre disque
  virtuel (partitionnement, systeme de fichiers, copie du systeme,
  installation du chargeur de demarrage), avec verification systematique
  que la configuration survit reellement a un redemarrage complet.
- *Un serveur refusant de demarrer depuis son disque malgre une
  installation identique aux autres* — un des serveurs (SRV-FTP) affichait
  systematiquement une erreur de demarrage ("Failed to load ldlinux.c32")
  meme apres plusieurs re-installations completes et identiques a celles
  qui avaient fonctionne sur les autres serveurs. La cause exacte n'a jamais
  ete identifiee avec certitude (probable corruption interne du fichier
  disque virtuel suite a des arrets forces repetes). Contourne efficacement
  en clonant integralement un serveur deja fonctionnel (disque + configuration
  materielle complete de la machine virtuelle) puis en reconfigurant son
  contenu (nom, adresse IP, service) — solution plus rapide et fiable que de
  continuer a deboguer un cas isole, et reutilisee ensuite pour creer
  rapidement les serveurs suivants.
- *Conflits d'identifiant de routeur OSPF* — plusieurs routeurs se
  retrouvaient reguliererement avec le meme identifiant OSPF (router-id)
  qu'un autre routeur du reseau, ce qui empechait leurs voisins de se
  former correctement. Corrige en forçant explicitement un identifiant
  unique sur chaque routeur concerne et en reinitialisant le processus OSPF
  pour appliquer le changement immediatement.
- *Identifiants reels commis dans le depot Git* — `devices.xlsx`, contenant
  de vrais identifiants de connexion utilises pour les tests, avait ete
  commis dans l'historique Git malgre une regle `.gitignore` — celle-ci
  n'empeche que le suivi de nouveaux fichiers, pas le retrait d'un fichier
  deja suivi avant son ajout au `.gitignore`. Corrige en retirant le fichier
  du suivi Git et en le remplaçant par `devices.xlsx.example`, avec des
  valeurs fictives.

Ce laboratoire sert desormais de base de test réel pour la nouvelle
fonctionnalite "Connexion" (voir section suivante) : connexion SSH multiple,
decouverte de topologie via CDP, et visualisation graphique interactive du
reseau.

![v1.6 Topologie GNS3](docs/screenshots/screenshot_v16_topologie.png)
![v1.6 Firewall Shorewall](docs/screenshots/screenshot_v16_firewall.png)
![v1.6 Test DMZ client externe](docs/screenshots/screenshot_v16_dmz_test.png)
![v1.6 SSH tous equipements](docs/screenshots/screenshot_v16_ssh.png)
![v1.6 Serveur Apache SRV-WEB](docs/screenshots/screenshot_v16_srvweb.png)
![v1.6 SFTP SRV-FTP](docs/screenshots/screenshot_v16_srvftp.png)
![v1.6 DNS SRV-DNS](docs/screenshots/screenshot_v16_srvdns.png)
![v1.6 Intranet nginx](docs/screenshots/screenshot_v16_srvintranet.png)
![v1.6 Syslog reçu](docs/screenshots/screenshot_v16_syslog.png)
![v1.6 ACL Finance bloquee](docs/screenshots/screenshot_v16_acl.png)

---

## Installation

```bash
pip install -r requirements.txt
```

## Lancer l'application

```bash
python main.py
```
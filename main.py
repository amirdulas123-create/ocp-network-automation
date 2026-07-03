import customtkinter as ctk          # Framework GUI (Tkinter stylise, dark/light mode)
import threading                     # Pour lancer les taches reseau sans geler l'UI
import openpyxl                      # Lecture du fichier devices.xlsx (liste des switches)
import os
import json
import subprocess                    # Utilise pour lancer la commande "ping" systeme
import ipaddress                     # Manipulation de sous-reseaux (ex: 192.168.1.0/24)
import socket                        # Test de ports ouverts (SSH/Telnet/HTTP/...)
from datetime import datetime
from netmiko import ConnectHandler   # Librairie pour se connecter en SSH aux switches Cisco
from concurrent.futures import ThreadPoolExecutor, as_completed  # Scan reseau en parallele
from tkinter import filedialog, PanedWindow  # Boite de dialogue "Parcourir un fichier" + separateur redimensionnable

HISTORY_FILE = os.path.join("data", "scan_history.json")   # Historique des scans reseau
SETTINGS_FILE = os.path.join("data", "settings.json")      # Preferences (theme dark/light)
COMMANDS_FILE = "commands.txt"                              # Commandes par defaut si la zone de texte est vide
# Tuples (mode clair, mode sombre) explicites pour tout ce qui vit dans un PanedWindow :
# un PanedWindow est un widget Tk brut, donc la detection automatique de couleur de
# CustomTkinter ("transparent", coins arrondis) s'y resout UNE seule fois au demarrage
# et ne suit plus le changement de theme — d'ou bandes/coins de la mauvaise couleur.
# Avec des tuples explicites, CustomTkinter rebascule tout seul a chaque toggle.
# Fond du PanedWindow = meme couleur que le fond des onglets CTkTabview, pour que les
# coins arrondis des textbox et la zone du sash se fondent dans le decor au lieu de
# ressortir en gris plus fonce. Le sash reste reperable grace a sashrelief="raised".
PANED_BG = ("gray86", "gray17")
TAB_BG = ("gray86", "gray17")

def load_devices():
    # Lit devices.xlsx : 1ere ligne = headers, chaque ligne suivante = un appareil
    wb = openpyxl.load_workbook("devices.xlsx")
    ws = wb.active
    headers = [cell.value for cell in ws[1]]
    return [dict(zip(headers, row)) for row in ws.iter_rows(min_row=2, values_only=True)]

def ping(ip):
    # Un seul ping ICMP (timeout 500ms) via la commande systeme Windows "ping"
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "500", str(ip)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return str(ip), result.returncode == 0

def detect_device(ip):
    # Teste des ports TCP courants pour deviner le type d'appareil (pas d'auth, juste connect())
    ports = {22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}
    open_ports = []
    for port, name in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            if sock.connect_ex((ip, port)) == 0:  # 0 = port ouvert
                open_ports.append(name)
            sock.close()
        except:
            pass
    if "SSH" in open_ports or "Telnet" in open_ports:
        return "Equipement reseau"
    elif "RDP" in open_ports:
        return "PC Windows"
    elif "HTTP" in open_ports or "HTTPS" in open_ports:
        return "Serveur Web"
    elif open_ports:
        return f"Hote ({', '.join(open_ports)})"
    else:
        return "Hote actif"

def scan_network(subnet):
    # Ping tous les hotes d'un sous-reseau en parallele (50 threads), puis detecte
    # le type de chaque appareil qui repond
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())
    alive = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip, is_alive = future.result()
            if is_alive:
                device_type = detect_device(ip)
                alive.append((ip, device_type))
    return sorted(alive, key=lambda x: x[0])

def load_history():
    # Charge l'historique des scans (liste vide si le fichier n'existe pas encore)
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            return json.load(f)
    return []

def save_history(history):
    os.makedirs("data", exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def load_settings():
    # Charge les preferences (theme). Dark par defaut si aucun fichier n'existe
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    return {"theme": "dark"}

def save_settings(settings):
    os.makedirs("data", exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

def theme_color(color_tuple):
    # tkinter.PanedWindow est un widget Tk brut (pas CustomTkinter) : il ne comprend
    # pas les tuples (couleur claire, couleur sombre) de CTk, il lui faut une couleur
    # resolue selon le mode d'apparence actuel.
    idx = 0 if ctk.get_appearance_mode() == "Light" else 1
    return color_tuple[idx]

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        # CustomTkinter, sur Windows, cache (withdraw) puis reaffiche (deiconify) la
        # fenetre a CHAQUE appel de set_appearance_mode() rien que pour recolorer la
        # barre de titre (voir ctk_tk.py::_windows_set_titlebar_color) — c'est ca la
        # cause du "disappear/appear" au changement de theme, pas notre code. Ce flag
        # documente par CustomTkinter desactive cette manipulation de fenetre : la
        # barre de titre garde sa couleur par defaut, mais tout le contenu (boutons,
        # fond, texte) change de couleur instantanement, sans aucun clignotement.
        self._deactivate_windows_window_header_manipulation = True
        self._push_running = False
        self._push_cancel = threading.Event()
        self.settings = load_settings()
        ctk.set_appearance_mode(self.settings.get("theme", "dark"))
        self._zoom = self.settings.get("zoom", 1.0)
        ctk.set_widget_scaling(self._zoom)
        self.title("OCP Network Automation")
        self.geometry("900x700")
        self.minsize(700, 600)  # empeche de redimensionner trop petit (UI cassee sinon)
        self.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "ocp_logo.ico"))
        self._build()

    def _build(self):
        # Layout principal : onglets (row 0) + bouton theme en bas (row 1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        tabs = ctk.CTkTabview(self, anchor="nw")
        tabs.grid(row=0, column=0, padx=16, pady=(16,0), sticky="nsew")
        tabs.add("Envoi Config")
        tabs.add("Sauvegarde")
        tabs.add("Scanner Reseau")
        self._build_push(tabs.tab("Envoi Config"))
        self._build_backup(tabs.tab("Sauvegarde"))
        self._build_scanner(tabs.tab("Scanner Reseau"))

        # Barre du bas : zoom (petit, a gauche du bouton theme) + bouton theme
        bottom_bar = ctk.CTkFrame(self, fg_color="transparent")
        bottom_bar.grid(row=1, column=0, padx=16, pady=8, sticky="e")

        ctk.CTkButton(bottom_bar, text="-", width=28, fg_color="gray30", hover_color="gray40",
                      command=self._zoom_out).pack(side="left", padx=(0,2))
        self._zoom_label = ctk.CTkLabel(bottom_bar, text=f"{round(self._zoom * 100)}%", width=45)
        self._zoom_label.pack(side="left", padx=2)
        ctk.CTkButton(bottom_bar, text="+", width=28, fg_color="gray30", hover_color="gray40",
                      command=self._zoom_in).pack(side="left", padx=(2,10))

        # Le texte du bouton indique l'action a venir, pas l'etat actuel
        theme_label = "Mode clair" if self.settings.get("theme") == "dark" else "Mode sombre"
        self._theme_btn = ctk.CTkButton(bottom_bar, text=theme_label, width=120,
                                         fg_color="gray30", hover_color="gray40",
                                         command=self._toggle_theme)
        self._theme_btn.pack(side="left")

    def _zoom_in(self):
        self._set_zoom(self._zoom + 0.1)

    def _zoom_out(self):
        self._set_zoom(self._zoom - 0.1)

    def _set_zoom(self, zoom):
        # Bornes raisonnables pour eviter un texte illisible (trop petit) ou une
        # fenetre qui deborde de l'ecran (trop grand)
        zoom = max(0.7, min(1.5, round(zoom, 2)))
        self._zoom = zoom
        ctk.set_widget_scaling(zoom)
        self._zoom_label.configure(text=f"{round(zoom * 100)}%")
        self.settings["zoom"] = zoom
        save_settings(self.settings)
        # La fenetre garde TOUJOURS la taille choisie par l'utilisateur (resize manuel
        # ou taille par defaut) — le zoom ne doit jamais y toucher. Si le contenu
        # grossi deborde de la fenetre existante, c'est aux widgets d'etre scrollables
        # (voir _build_push et _build_scanner), pas a la fenetre de s'agrandir.

    def _toggle_theme(self):
        # La cause du glitch (voir __init__) est desactivee via
        # _deactivate_windows_window_header_manipulation : plus besoin de bidouiller
        # la fenetre ici, set_appearance_mode() se contente de recolorer les widgets.
        current = self.settings.get("theme", "dark")
        new_theme = "light" if current == "dark" else "dark"
        self.settings["theme"] = new_theme
        save_settings(self.settings)

        ctk.set_appearance_mode(new_theme)
        self._theme_btn.configure(text="Mode clair" if new_theme == "dark" else "Mode sombre")

        # Les PanedWindow (_push_paned, _scan_paned) sont des widgets Tk bruts : leur
        # couleur ne suit pas automatiquement set_appearance_mode(), il faut la
        # reappliquer nous-memes.
        paned_bg = theme_color(PANED_BG)
        for paned in (getattr(self, "_push_paned", None), getattr(self, "_scan_paned", None)):
            if paned is not None:
                paned.configure(bg=paned_bg)

    def _build_push(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(5,10))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Envoi de Configuration Multi-Appareils",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Tapez des commandes ou chargez un fichier .txt — vide = commands.txt utilise",
                     text_color="gray").grid(row=1, column=0, sticky="w")

        # Buttons row
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0,5))
        # Largeur fixe : le texte change ("Envoyer a tous les appareils" -> "Envoi en
        # cours...") pendant l'envoi, et sans largeur fixe le canvas interne du bouton
        # se redimensionne pour suivre le texte plus court, ce qui laisse un contour
        # fantome de l'ancienne taille le temps d'un repaint sur Windows (glitch visuel).
        self._push_btn = ctk.CTkButton(btn_frame, text="Envoyer a tous les appareils",
                      width=220,
                      fg_color="#1d4ed8", hover_color="#1e40af",
                      command=self._start_push)
        self._push_btn.pack(side="left", padx=(0,10))
        ctk.CTkButton(btn_frame, text="Parcourir .txt",
                      fg_color="gray30", hover_color="gray40",
                      command=self._browse_commands
                      ).pack(side="left")

        # Commands label
        ctk.CTkLabel(frame, text="Commandes :").grid(row=2, column=0, sticky="w", pady=(5,0))

        # Zone de commandes + log dans un PanedWindow : le sash (barre entre les deux)
        # se tire a la souris pour agrandir/reduire chaque zone, au lieu d'une hauteur
        # fixe ou d'un partage automatique qui ne convient jamais a tout le monde.
        # opaqueresize=False : le redimensionnement ne s'applique qu'au relachement de
        # la souris (une ligne fantome pendant le drag) — le resize continu pendant le
        # drag faisait glitcher les widgets CustomTkinter contenus dans les panes.
        self._push_paned = PanedWindow(frame, orient="vertical", sashwidth=6, sashrelief="raised",
                                        bg=theme_color(PANED_BG), bd=0, opaqueresize=False)
        self._push_paned.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(2,5))

        # Commands text area (editable, une commande par ligne)
        # bg_color=PANED_BG en tuple : la couleur derriere les coins arrondis suit le
        # theme automatiquement (voir commentaire de PANED_BG en haut du fichier)
        self._commands_box = ctk.CTkTextbox(self._push_paned, font=ctk.CTkFont(family="Consolas", size=11),
                                             bg_color=PANED_BG)
        self._push_paned.add(self._commands_box, minsize=60, height=150)

        # Log output (lecture seule, resultat de l'envoi)
        self._push_log = ctk.CTkTextbox(self._push_paned, font=ctk.CTkFont(family="Consolas", size=11),
                                         state="disabled", bg_color=PANED_BG)
        self._push_paned.add(self._push_log, minsize=60, height=250)

    def _browse_commands(self):
        # Charge un .txt et remplace le contenu de la zone de texte des commandes
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            self._commands_box.delete("0.0", "end")
            self._commands_box.insert("0.0", content)

    def _build_backup(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Sauvegarde de Configuration",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, sticky="w", pady=(5,0))
        ctk.CTkButton(frame, text="Sauvegarder tous les appareils",
                      fg_color="#15803d", hover_color="#166534",
                      command=lambda: threading.Thread(target=self._run_backup, daemon=True).start()
                      ).grid(row=0, column=1, padx=10, pady=5, sticky="e")

        # Description sur sa propre ligne, sur toute la largeur (columnspan=2) : avant,
        # elle partageait la ligne 0 avec le bouton vert, qui la coupait a fort zoom
        # car column 1 (bouton) n'a pas de weight et prend toute la place qu'il lui faut
        ctk.CTkLabel(frame, text="Sauvegarde la config active de tous les appareils dans des fichiers horodates",
                     text_color="gray").grid(row=1, column=0, columnspan=2, sticky="w")

        self._backup_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=11), state="disabled")
        self._backup_log.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)

    def _build_scanner(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", pady=5)
        ctk.CTkLabel(top, text="Sous-reseau :").pack(side="left", padx=5)
        self._subnet_entry = ctk.CTkEntry(top, placeholder_text="192.168.1.0/24", width=200)
        self._subnet_entry.pack(side="left", padx=5)
        ctk.CTkButton(top, text="Scanner", fg_color="#dc2626", hover_color="#b91c1c",
                      command=lambda: threading.Thread(target=self._run_scan, daemon=True).start()
                      ).pack(side="left", padx=5)

        # Log de scan + historique dans un PanedWindow : le sash se tire a la souris
        # pour agrandir/reduire chaque zone, au lieu d'un partage fixe qui laisse soit
        # le log soit l'historique trop petit selon le zoom/la taille de fenetre.
        # opaqueresize=False + couleurs en tuples : voir _build_push et PANED_BG
        self._scan_paned = PanedWindow(frame, orient="vertical", sashwidth=6, sashrelief="raised",
                                        bg=theme_color(PANED_BG), bd=0, opaqueresize=False)
        self._scan_paned.grid(row=1, column=0, sticky="nsew", pady=(5,0))

        self._scan_log = ctk.CTkTextbox(self._scan_paned, font=ctk.CTkFont(family="Consolas", size=11),
                                         state="disabled", bg_color=PANED_BG)
        self._scan_paned.add(self._scan_log, minsize=60, height=200)

        # fg_color explicite (pas "transparent") : a travers le PanedWindow Tk brut,
        # la transparence se fige sur la couleur du demarrage et ne suit plus le theme
        history_pane = ctk.CTkFrame(self._scan_paned, fg_color=TAB_BG, corner_radius=0)
        history_pane.grid_columnconfigure(0, weight=1)
        history_pane.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(history_pane, text="Historique des scans",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, sticky="w", pady=(5,5))
        # Frame scrollable : l'historique peut devenir long avec le temps
        self._history_frame = ctk.CTkScrollableFrame(history_pane)
        self._history_frame.grid(row=1, column=0, sticky="nsew")
        self._history_frame.grid_columnconfigure(0, weight=1)
        self._scan_paned.add(history_pane, minsize=100, height=250)
        self._load_history_ui()

    def _load_history_ui(self):
        # Reconstruit l'affichage de l'historique depuis le JSON (repart de zero a chaque appel)
        for widget in self._history_frame.winfo_children():
            widget.destroy()
        history = load_history()
        for i, entry in enumerate(history):
            row = ctk.CTkFrame(self._history_frame, fg_color="transparent")
            row.grid(row=i, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=entry["timestamp"], text_color="gray", width=160).grid(row=0, column=0, padx=5)
            lbl = ctk.CTkLabel(row, text=entry["target"], cursor="hand2")
            lbl.grid(row=0, column=1, sticky="w")
            # Clic sur le sous-reseau -> le remet dans le champ de saisie du scan
            lbl.bind("<Button-1>", lambda e, t=entry["target"]: (
                self._subnet_entry.delete(0, "end"),
                self._subnet_entry.insert(0, t)
            ))
            # text_color/hover_color fixes en tuple (mode clair, mode sombre) : avec
            # fg_color="transparent" et la couleur de texte par defaut du theme (blanc),
            # le "x" devenait invisible sur fond clair en mode light.
            ctk.CTkButton(row, text="x", width=30, fg_color="transparent",
                          text_color=("gray20", "gray90"),
                          hover_color=("gray75", "gray30"),
                          command=lambda t=entry["target"]: self._delete_history(t)
                          ).grid(row=0, column=2, padx=5)

    def _delete_history(self, target):
        history = [h for h in load_history() if h["target"] != target]
        save_history(history)
        # _load_history_ui() detruit tous les widgets de _history_frame, y compris le
        # bouton "x" en train de traiter CE clic (son animation de clic est planifiee
        # via after() et reference le widget) -> le detruire tout de suite gele/casse
        # l'UI. On differe la reconstruction pour laisser le clic se terminer d'abord.
        self.after(0, self._load_history_ui)

    def _run_scan(self):
        # Scanne le sous-reseau saisi, affiche les resultats au fur et a mesure, sauvegarde l'historique
        box = self._scan_log
        self._clear(box)
        subnet = self._subnet_entry.get().strip()
        if not subnet:
            self._log(box, "Entrez un sous-reseau valide")
            return
        self._log(box, f"Scan de {subnet} en cours...")
        try:
            alive = scan_network(subnet)
            for ip, device_type in alive:
                self._log(box, f"✓ {ip} — {device_type}")
            self._log(box, f"\nTotal: {len(alive)} hotes actifs")
            # Retire l'ancienne entree du meme sous-reseau, la remet en tete avec la date du jour
            history = load_history()
            history = [h for h in history if h["target"] != subnet]
            history.insert(0, {"target": subnet, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            save_history(history)
            self.after(0, self._load_history_ui)
        except Exception as e:
            self._log(box, f"Erreur: {e}")

    def _start_push(self):
        # Le bouton fait office de start ET stop : pendant l'envoi, un nouveau clic
        # ne relance pas un thread (ce qui recreerait le bug des clics multiples) —
        # il demande juste l'arret via un threading.Event verifie entre deux appareils.
        if self._push_running:
            self._push_cancel.set()
            self._push_btn.configure(state="disabled", text="Arret en cours...")
            return
        self._push_running = True
        self._push_cancel.clear()
        self._push_btn.configure(fg_color="#dc2626", hover_color="#b91c1c", text="Arreter l'envoi")
        threading.Thread(target=self._run_push, daemon=True).start()

    def _run_push(self):
        try:
            self._run_push_inner()
        finally:
            self._push_running = False
            self.after(0, lambda: self._push_btn.configure(
                state="normal", fg_color="#1d4ed8", hover_color="#1e40af",
                text="Envoyer a tous les appareils"))

    def _run_push_inner(self):
        # Envoie les commandes de configuration a tous les appareils de devices.xlsx
        box = self._push_log
        self._clear(box)
        devices = load_devices()

        # Get commands from text area or fallback to commands.txt
        text_content = self._commands_box.get("0.0", "end").strip()
        if text_content:
            commands = [line.strip() for line in text_content.splitlines() if line.strip()]
        elif os.path.exists(COMMANDS_FILE):
            with open(COMMANDS_FILE, "r", encoding="utf-8") as f:
                commands = [line.strip() for line in f if line.strip()]
        else:
            self._log(box, "Aucune commande trouvee — zone de texte vide et commands.txt introuvable")
            return

        # commands.txt peut exister mais etre vide (ou ne contenir que des lignes vides) :
        # il faut verifier le CONTENU, pas juste la presence du fichier, sinon on continue
        # avec une liste vide -> connexion aux appareils pour "envoyer" 0 commande et un
        # faux message de succes ("config appliquee") alors que rien n'a ete fait.
        if not commands:
            self._log(box, "Aucune commande trouvee — zone de texte et commands.txt sont vides")
            return

        self._log(box, f"Commandes a envoyer: {len(commands)}")
        for d in devices:
            # Verifie AVANT chaque appareil si l'utilisateur a demande l'arret (bouton
            # "Arreter l'envoi"). On ne peut pas interrompre une connexion SSH deja en
            # cours au milieu d'un send_config_set, mais on evite au moins de continuer
            # sur les appareils suivants.
            if self._push_cancel.is_set():
                self._log(box, "Envoi arrete par l'utilisateur")
                return
            self._log(box, f"Connexion a {d['name']}...")
            try:
                conn = ConnectHandler(
                    device_type=d["device_type"], host=d["host"],
                    port=int(d["port"]), username=d["username"],
                    password=d["password"], secret=d["secret"],
                    # Desactive certains algos SSH modernes non supportes par les vieux Cisco
                    disabled_algorithms=dict(
                        kex=["curve25519-sha256", "curve25519-sha256@libssh.org",
                             "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
                             "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256"],
                        pubkeys=["rsa-sha2-512", "rsa-sha2-256"]
                    )
                )
                conn.enable()                     # mode privilegie
                output = conn.send_config_set(commands)  # config terminal + envoi des commandes
                conn.save_config()                # equivalent "write memory"
                conn.disconnect()

                # Le switch peut repondre "% Invalid input" / "% Incomplete command" etc.
                # sans que Netmiko leve d'exception -> on verifie nous-memes la sortie
                error_markers = ["% Invalid input", "% Incomplete command",
                                  "% Ambiguous command", "% Unrecognized command"]
                errors_found = [line for line in output.splitlines()
                                 if any(marker in line for marker in error_markers)]
                if errors_found:
                    self._log(box, f"⚠ {d['name']} — commande(s) rejetee(s) par le switch:")
                    for line in errors_found:
                        self._log(box, f"   {line.strip()}")
                else:
                    self._log(box, f"✓ {d['name']} — config appliquee")
            except Exception as e:
                # Continue sur les appareils suivants meme si celui-ci echoue
                self._log(box, f"✗ {d['name']} — {e}")

    def _run_backup(self):
        # Recupere show running-config de chaque appareil et le sauvegarde dans un fichier horodate
        box = self._backup_log
        self._clear(box)
        devices = load_devices()
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_dir = os.path.join("backups", timestamp)  # un dossier par session de sauvegarde
        os.makedirs(backup_dir, exist_ok=True)
        for d in devices:
            self._log(box, f"Connexion a {d['name']}...")
            try:
                conn = ConnectHandler(
                    device_type=d["device_type"], host=d["host"],
                    port=int(d["port"]), username=d["username"],
                    password=d["password"], secret=d["secret"],
                    disabled_algorithms=dict(
                        kex=["curve25519-sha256", "curve25519-sha256@libssh.org",
                             "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
                             "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256"],
                        pubkeys=["rsa-sha2-512", "rsa-sha2-256"]
                    )
                )
                conn.enable()
                output = conn.send_command("show running-config")
                conn.disconnect()
                filename = os.path.join(backup_dir, f"{d['name']}_{timestamp}.txt")
                with open(filename, "w") as f:
                    f.write(output)
                self._log(box, f"✓ {d['name']} — sauvegarde: {filename}")
            except Exception as e:
                self._log(box, f"✗ {d['name']} — {e}")

    def _log(self, box, msg):
        # _run_push_inner/_run_backup/_run_scan tournent dans des threads en arriere-
        # plan, mais Tkinter n'est PAS thread-safe : manipuler des widgets (et surtout
        # appeler .update(), qui force le traitement de TOUTE la queue d'evenements Tk)
        # depuis un thread autre que le principal course avec les redraws internes de
        # CustomTkinter et provoque des TclError aleatoires ("invalid command name"),
        # surtout quand plusieurs operations tournent en meme temps. self.after(0, ..)
        # est le mecanisme thread-safe standard pour renvoyer le travail au thread
        # principal (fonctionne aussi si _log est deja appele depuis le thread principal).
        self.after(0, self._log_ui, box, msg)

    def _log_ui(self, box, msg):
        # Ecrit dans une textbox en lecture seule : deverrouille, ecrit, reverrouille, scroll bas
        box.configure(state="normal")
        box.insert("end", msg + "\n")
        box.see("end")
        box.configure(state="disabled")

    def _clear(self, box):
        self.after(0, self._clear_ui, box)

    def _clear_ui(self, box):
        box.configure(state="normal")
        box.delete("0.0", "end")
        box.configure(state="disabled")

if __name__ == "__main__":
    app = App()
    app.mainloop()
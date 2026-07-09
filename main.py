import customtkinter as ctk          # Framework GUI (Tkinter stylise, dark/light mode)
import threading                     # Pour lancer les taches reseau sans geler l'UI
import os
import json
import re                            # Parsing des warnings/erreurs remontes par nmap
import time                          # Chronometrage du scan (temps total)
import shlex                         # Decoupage de la ligne de commande nmap (comme python-nmap)
import subprocess                    # Utilise pour lancer "ping" systeme et nmap.exe
import ipaddress                     # Manipulation de sous-reseaux (ex: 192.168.1.0/24)
import socket                        # Test de ports ouverts (SSH/Telnet/HTTP/...)
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed  # Scan reseau en parallele
from tkinter import filedialog, PanedWindow  # Boite de dialogue "Parcourir un fichier" + separateur redimensionnable
# netmiko (SSH) et openpyxl (lecture Excel) sont importes PARESSEUSEMENT au moment
# ou on en a besoin (clic sur un bouton), pas au chargement du module : leur import
# coute ~0.9s a eux deux et rallongeait d'autant le demarrage de l'app avant meme
# l'affichage de la fenetre. nmap est deja importe paresseusement (voir plus bas).

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
    import openpyxl  # import paresseux (voir en-tete) : ~0.5s, inutile au demarrage
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

class ScanCancelled(Exception):
    # Levee quand l'utilisateur demande l'arret du scan (bouton "Arreter le scan").
    # Remonte jusqu'a _run_scan_inner qui l'affiche proprement au lieu d'un "Erreur".
    pass


def scan_network(subnet, cancel=None):
    # Ping tous les hotes d'un sous-reseau en parallele (50 threads), puis detecte
    # le type de chaque appareil qui repond. cancel (threading.Event) permet d'arreter
    # entre deux hotes : on ne soumet plus de nouveau travail et on coupe l'attente.
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())
    alive = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping, ip): ip for ip in hosts}
        for future in as_completed(futures):
            if cancel is not None and cancel.is_set():
                # cancel_futures : n'attend pas les pings encore en file d'attente
                executor.shutdown(wait=False, cancel_futures=True)
                raise ScanCancelled()
            ip, is_alive = future.result()
            if is_alive:
                device_type = detect_device(ip)
                alive.append((ip, device_type))
    return sorted(alive, key=lambda x: x[0])

# ---------------------------------------------------------------------------
# Scan avance via Nmap (python-nmap)
# ---------------------------------------------------------------------------
# Ports TCP scannes par defaut : les memes que l'ancien scan basique
# (22/23/80/443/3389) + quelques ports pertinents en environnement Cisco/IT
# (FTP, NETCONF, consoles web alternatives). Modifiable via le champ "Ports"
# de l'onglet Scanner.
DEFAULT_SCAN_PORTS = "21,22,23,80,443,830,3389,8080,8443"
PORT_LABELS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
    830: "NETCONF", 3389: "RDP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}
# Timeout par hote : un lab GNS3 local repond vite. 90s etait inutilement long et
# faisait trainer le scan (3-4 min) quand quelques IPs ne repondaient pas aux
# sondes de decouverte -> 30s suffit largement en LAN/lab.
HOST_TIMEOUT = "30s"

def _classify_device(open_ports):
    # Meme logique de classification que detect_device() (le fallback), mais a
    # partir des numeros de port ouverts remontes par Nmap. NETCONF (830) est
    # ajoute comme signe d'equipement reseau (frequent sur du Cisco recent / GNS3).
    if any(p in open_ports for p in (22, 23, 830)):
        return "Equipement reseau"
    if 3389 in open_ports:
        return "PC Windows"
    if any(p in open_ports for p in (80, 443, 8080, 8443)):
        return "Serveur Web"
    return "Hote actif"

def _best_os_match(host_info):
    # Renvoie la meilleure hypothese d'OS ("Linux 2.6.x (95%)") si -O a tourne,
    # sinon None. Nmap trie osmatch par precision decroissante -> [0] = meilleur.
    osmatch = host_info.get("osmatch", [])
    if not osmatch:
        return None
    best = osmatch[0]
    name = (best.get("name") or "").strip()
    if not name:
        return None
    accuracy = best.get("accuracy", "")
    return f"{name} ({accuracy}%)" if accuracy else name

def _format_nmap_host(host_info):
    # Construit la ligne de details d'un hote a partir des donnees Nmap, dans le
    # meme esprit que detect_device() mais enrichi : type d'equipement, services
    # avec produit/version (ex "SSH: OpenSSH 8.2"), et OS si disponible.
    services = []
    open_ports = []
    for port in host_info.all_tcp():
        pdata = host_info["tcp"][port]
        if pdata.get("state") != "open":
            continue
        open_ports.append(port)
        label = PORT_LABELS.get(port, pdata.get("name") or str(port))
        product = (pdata.get("product") or "").strip()
        version = (pdata.get("version") or "").strip()
        if product:
            services.append(f"{label}: {product}" + (f" {version}" if version else ""))
        else:
            services.append(label)
    detail = _classify_device(open_ports)
    if services:
        detail += " [" + ", ".join(services) + "]"
    os_label = _best_os_match(host_info)
    if os_label:
        detail += f" | OS: {os_label}"
    return detail

def _is_privilege_error(msg):
    # La detection d'OS (-O) exige les privileges admin/root. Sans eux, Nmap
    # s'arrete avec un message du genre "You requested a scan type which requires
    # root privileges." que python-nmap propage en PortScannerError.
    m = msg.lower()
    return "privile" in m or "requires root" in m or "requested a scan type" in m

def _ip_sort_key(item):
    # Tri numerique des IP (1.2.3.10 apres 1.2.3.9, pas l'inverse lexical).
    # Repli sur le tri texte si jamais Nmap remonte un nom d'hote.
    try:
        return (0, ipaddress.ip_address(item[0]))
    except ValueError:
        return (1, item[0])

def _host_responded(host_info):
    # En mode -Pn (aucune decouverte), Nmap marque TOUTES les IPs comme "up".
    # Un hote reellement present repond au moins par un RST sur un port ferme (ou
    # expose un port ouvert) ; une IP morte ne renvoie que du 'filtered' ou rien.
    # On ne garde donc que les hotes qui ont vraiment repondu sur un port, pour ne
    # pas lister les 254 IPs du sous-reseau.
    for port in host_info.all_tcp():
        if host_info["tcp"][port].get("state") in ("open", "closed"):
            return True
    return False

def _run_nmap_process(nm, hosts, ports, arguments, cancel):
    # Replique PortScanner.scan() (python-nmap) mais via un Popen qu'on garde la main
    # dessus pour pouvoir le TERMINER sur demande d'annulation. nm.scan() est bloquant
    # et non interruptible : il lance nmap.exe et attend .communicate() jusqu'a la fin,
    # sans aucun point de controle. Ici on lance nmap.exe nous-memes (-oX - = XML sur
    # stdout), on draine stdout/stderr dans des threads (evite l'interblocage si le
    # buffer de pipe se remplit), et on sonde cancel toutes les 150ms pour pouvoir
    # .terminate() nmap.exe immediatement. Le XML recolte est ensuite parse par
    # python-nmap (analyse_nmap_xml_scan) pour rester 100% compatible avec nm[host].
    args = ([nm._nmap_path, "-oX", "-"] + shlex.split(hosts)
            + (["-p", ports] if ports else []) + shlex.split(arguments))
    proc = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_holder, err_holder = {}, {}
    t_out = threading.Thread(target=lambda: out_holder.__setitem__("v", proc.stdout.read()), daemon=True)
    t_err = threading.Thread(target=lambda: err_holder.__setitem__("v", proc.stderr.read()), daemon=True)
    t_out.start()
    t_err.start()
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            proc.terminate()  # TerminateProcess sur Windows : coupe nmap.exe pour de vrai
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        time.sleep(0.15)
    t_out.join()
    t_err.join()
    if cancel is not None and cancel.is_set():
        raise ScanCancelled()
    xml_output = out_holder.get("v", b"")
    nmap_err = bytes.decode(err_holder.get("v", b""))
    # Meme tri erreurs/warnings que PortScanner.scan() : un simple "Warning:" n'est pas
    # fatal, le reste de stderr l'est (fait lever PortScannerError par analyse_nmap_xml_scan).
    nmap_err_keep_trace, nmap_warn_keep_trace = [], []
    if len(nmap_err) > 0:
        regex_warning = re.compile("^Warning: .*", re.IGNORECASE)
        for line in nmap_err.split(os.linesep):
            if len(line) > 0:
                if regex_warning.search(line) is not None:
                    nmap_warn_keep_trace.append(line + os.linesep)
                else:
                    nmap_err_keep_trace.append(nmap_err)
    return nm.analyse_nmap_xml_scan(nmap_xml_output=xml_output, nmap_err=nmap_err,
                                    nmap_err_keep_trace=nmap_err_keep_trace,
                                    nmap_warn_keep_trace=nmap_warn_keep_trace)


def _run_nmap_scan(nm, subnet, ports, log, skip_discovery=False, cancel=None):
    import nmap  # deja importe avec succes par l'appelant, juste pour PortScannerError
    # Decouverte d'hote :
    # - Par defaut, sur un LAN Ethernet, Nmap fait de l'ARP (tres fiable pour les
    #   PC), auquel on ajoute -PE (ICMP echo request) pour les equipements qui
    #   repondent au ping mais pas forcement aux autres sondes.
    # - skip_discovery (-Pn) : saute completement la phase de decouverte et scanne
    #   directement les ports. Indispensable sur certains labs GNS3 ou un routeur
    #   virtuel repond au ping Windows manuel mais est ignore par la decouverte
    #   Nmap (ARP/ICMP qui timeout). Sur un petit lab, scanner quelques IPs "mortes"
    #   en plus coute bien moins cher que de rater un equipement reel.
    discovery = "-Pn" if skip_discovery else "-PE"
    # -T5 (au lieu de -T4) : timing le plus agressif, adapte a un lab/LAN local rapide
    #   ou la latence est faible et la perte de paquets negligeable. --min-hostgroup 64
    #   force Nmap a scanner les hotes par gros paquets (64 a la fois) au lieu de son
    #   decoupage par defaut plus petit : sur un /24 (254 hotes) ca augmente nettement
    #   le parallelisme inter-hotes et raccourcit le temps total, surtout en -Pn ou les
    #   254 IPs sont toutes scannees. --max-retries 1 coupe les retransmissions de
    #   sondes (inutiles en LAN) qui faisaient trainer les IPs sans reponse.
    base_args = f"-sV -T5 --min-hostgroup 64 --max-retries 1 --host-timeout {HOST_TIMEOUT} {discovery}"
    log(f"Decouverte d'hote : {'-Pn (aucune, scan direct des ports)' if skip_discovery else '-PE (ICMP echo) + ARP par defaut'}")
    try:
        _run_nmap_process(nm, subnet, ports, base_args + " -O", cancel)
    except nmap.PortScannerError as e:
        if _is_privilege_error(str(e)):
            log("Detection d'OS (-O) indisponible : privileges admin/root requis.")
            log("  -> Scan poursuivi sans detection d'OS (les versions de services restent detectees).")
            _run_nmap_process(nm, subnet, ports, base_args, cancel)
        else:
            raise
    results = []
    for host in nm.all_hosts():
        host_info = nm[host]
        # En -Pn toutes les IPs sont "up" : on filtre sur une vraie reponse de port.
        # Sinon (decouverte active), Nmap a deja valide l'etat "up" de l'hote.
        if skip_discovery:
            if not _host_responded(host_info):
                continue
        elif host_info.state() != "up":
            continue
        results.append((host, _format_nmap_host(host_info)))
    found = sorted(results, key=_ip_sort_key)
    log(f"{len(found)} hote(s) actif(s) detecte(s).")
    if not found and not skip_discovery:
        log("Aucun hote detecte. Si vous savez qu'un hote repond au ping, "
            "cochez 'Sans decouverte (-Pn)' et relancez.")
    return found

def scan_network_smart(subnet, log, ports=DEFAULT_SCAN_PORTS, skip_discovery=False, cancel=None):
    # Point d'entree du scan : tente Nmap (detection OS + versions de services) et
    # retombe automatiquement sur scan_network() (ping + socket) si python-nmap ou
    # le binaire nmap manque, ou si le scan Nmap echoue. log(msg) ecrit dans l'UI.
    # cancel (threading.Event) est propage jusqu'a nmap.exe pour l'arret immediat.
    ports = (ports or DEFAULT_SCAN_PORTS).strip() or DEFAULT_SCAN_PORTS
    try:
        import nmap
    except ImportError:
        log("Nmap non disponible (module python-nmap absent) — scan basique utilise.")
        log("  Pour le scan avance : pip install python-nmap")
        return scan_network(subnet, cancel=cancel)
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        log("Nmap non disponible (binaire 'nmap' introuvable) — scan basique utilise.")
        log("  Installez Nmap : https://nmap.org/download.html puis pip install python-nmap")
        return scan_network(subnet, cancel=cancel)
    try:
        log(f"Scan Nmap (-sV) des ports {ports}...")
        return _run_nmap_scan(nm, subnet, ports, log, skip_discovery=skip_discovery, cancel=cancel)
    except nmap.PortScannerError as e:
        log(f"Erreur Nmap : {e}")
        log("Repli sur le scan basique.")
        return scan_network(subnet, cancel=cancel)

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
        self._scan_running = False
        self._scan_cancel = threading.Event()
        self.settings = load_settings()
        ctk.set_appearance_mode(self.settings.get("theme", "dark"))
        self._zoom = self.settings.get("zoom", 1.0)
        ctk.set_widget_scaling(self._zoom)
        self.title("OCP Network Automation")
        self.geometry("900x700")
        self.minsize(700, 600)  # empeche de redimensionner trop petit (UI cassee sinon)
        # Icone de fenetre : purement decoratif. Un .ico manquant, corrompu ou sur un
        # chemin lent ne doit jamais empecher (ni ralentir bruyamment) le demarrage de
        # l'app -> try/except silencieux, l'app tourne avec l'icone Tk par defaut.
        try:
            self.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "ocp_logo.ico"))
        except Exception:
            pass
        self._build()

    def _build(self):
        # Police mono partagee par toutes les zones de texte (commandes/logs) : une
        # seule CTkFont reutilisee au lieu d'en instancier une identique par textbox.
        self._mono_font = ctk.CTkFont(family="Consolas", size=11)

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

    def _wrap_on_resize(self, label, pad=28):
        # Fait que le texte du label REVIENNE A LA LIGNE selon la largeur reelle
        # disponible, au lieu d'etre tronque quand la fenetre est etroite (surtout a
        # fort zoom). On suit le <Configure> du conteneur du label et on ajuste son
        # wraplength (en pixels). Le garde-fou "si la valeur change vraiment" evite de
        # reconfigurer le label a chaque pixel -> cout negligeable pendant un resize.
        parent = label.master
        def _update(event):
            wl = max(120, event.width - pad)
            if label.cget("wraplength") != wl:
                label.configure(wraplength=wl)
        parent.bind("<Configure>", _update, add="+")

    def _build_push(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        # Header
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(5,10))
        header.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(header, text="Envoi de Configuration Multi-Appareils",
                             font=ctk.CTkFont(size=15, weight="bold"), justify="left")
        title.grid(row=0, column=0, sticky="w")
        # justify="left" + wraplength responsive : le texte passe a la ligne au lieu
        # d'etre coupe en fenetre etroite/zoomee (voir _wrap_on_resize).
        desc = ctk.CTkLabel(header, text="Tapez des commandes ou chargez un fichier .txt — vide = commands.txt utilise",
                            text_color="gray", justify="left")
        desc.grid(row=1, column=0, sticky="w")
        self._wrap_on_resize(title)
        self._wrap_on_resize(desc)

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
        self._commands_box = ctk.CTkTextbox(self._push_paned, font=self._mono_font,
                                             bg_color=PANED_BG)
        self._push_paned.add(self._commands_box, minsize=60, height=150)

        # Log output (lecture seule, resultat de l'envoi)
        # wrap="none" : pas de retour a la ligne automatique -> les lignes longues
        # (ex erreurs Netmiko) restent sur une seule ligne. CTkTextbox affiche alors
        # tout seul sa scrollbar horizontale interne (_x_scrollbar, gere par
        # _check_if_scrollbars_needed) quand une ligne deborde, et la masque sinon.
        self._push_log = ctk.CTkTextbox(self._push_paned, font=self._mono_font, wrap="none",
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
        frame.grid_rowconfigure(3, weight=1)

        # Titre, description et bouton chacun sur SA propre ligne (ancres a gauche) :
        # avant, le titre et le bouton partageaient la ligne 0 et, en fenetre etroite
        # (ou a fort zoom), le bouton sans weight prenait toute sa place et repoussait /
        # tronquait le titre. En les empilant (comme la description l'etait deja), plus
        # aucun element n'est en concurrence de largeur ni pousse hors de l'ecran.
        title = ctk.CTkLabel(frame, text="Sauvegarde de Configuration",
                             font=ctk.CTkFont(size=15, weight="bold"), justify="left")
        title.grid(row=0, column=0, sticky="w", pady=(5,0))
        # wraplength responsive : le texte revient a la ligne au lieu d'etre tronque
        # en fenetre etroite/zoomee (voir _wrap_on_resize).
        desc = ctk.CTkLabel(frame, text="Sauvegarde la config active de tous les appareils dans des fichiers horodates",
                            text_color="gray", justify="left")
        desc.grid(row=1, column=0, sticky="w")
        self._wrap_on_resize(title)
        self._wrap_on_resize(desc)
        ctk.CTkButton(frame, text="Sauvegarder tous les appareils",
                      fg_color="#15803d", hover_color="#166534",
                      command=lambda: threading.Thread(target=self._run_backup, daemon=True).start()
                      ).grid(row=2, column=0, pady=(8,5), sticky="w")

        # wrap="none" -> scrollbar horizontale interne auto quand une ligne deborde (voir _build_push)
        self._backup_log = ctk.CTkTextbox(frame, font=self._mono_font, wrap="none", state="disabled")
        self._backup_log.grid(row=3, column=0, sticky="nsew", pady=10)

    def _build_scanner(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Barre du haut en GRILLE (et non pack(side="left")) pour rester responsive.
        # Chaque champ est sur SA PROPRE LIGNE, a largeur fixe et ancre a gauche
        # (sticky="w", label en colonne 0, champ en colonne 1) :
        #  - largeur fixe -> le champ garde une taille normale et NE S'ETIRE PAS sur
        #    toute la fenetre quand elle est large (regression "champ long af" quand on
        #    utilisait sticky="ew" + weight) ;
        #  - un seul couple label+champ par ligne -> ca tient meme en fenetre etroite a
        #    fort zoom, sans jamais deborder hors ecran (le probleme d'origine venait
        #    d'avoir subnet + ports + bouton + checkbox tous sur une meme ligne packee).
        # Le bouton Scanner + la checkbox -Pn sont sur leur propre ligne (row 2).
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", pady=5)
        ctk.CTkLabel(top, text="Sous-reseau :").grid(row=0, column=0, padx=(5, 8), pady=(0, 6), sticky="w")
        self._subnet_entry = ctk.CTkEntry(top, placeholder_text="192.168.1.0/24", width=200)
        self._subnet_entry.grid(row=0, column=1, pady=(0, 6), sticky="w")
        # Ports optionnels : vide = DEFAULT_SCAN_PORTS. Accepte la syntaxe Nmap
        # (ex "22,23,80" ou "1-1024"). Le placeholder montre la valeur par defaut.
        ctk.CTkLabel(top, text="Ports :").grid(row=1, column=0, padx=(5, 8), pady=(0, 6), sticky="w")
        self._ports_entry = ctk.CTkEntry(top, placeholder_text=DEFAULT_SCAN_PORTS, width=260)
        self._ports_entry.grid(row=1, column=1, pady=(0, 6), sticky="w")
        # Bouton + checkbox sur leur propre ligne (leur propre sous-frame packe a gauche) :
        # ils gardent leur taille naturelle sans jamais deborder, quelle que soit la
        # largeur de la fenetre.
        controls = ctk.CTkFrame(top, fg_color="transparent")
        controls.grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 0))
        # Largeur fixe du bouton : le texte passe de "Scanner" a "Arreter le scan"
        # pendant le scan ; sans largeur fixe, le retrecissement laisse un contour
        # fantome sur Windows (meme raison que le bouton d'envoi, voir _build_push).
        self._scan_btn = ctk.CTkButton(controls, text="Scanner", width=130,
                                       fg_color="#dc2626", hover_color="#b91c1c",
                                       command=self._start_scan)
        self._scan_btn.pack(side="left", padx=(5, 10))
        # -Pn : saute la decouverte d'hote et scanne directement les ports. A cocher
        # quand un hote (ex routeur GNS3) repond au ping mais est ignore par la
        # decouverte Nmap par defaut (voir _run_nmap_scan).
        self._pn_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(controls, text="Sans decouverte (-Pn)", variable=self._pn_var).pack(side="left")

        # Log de scan + historique dans un PanedWindow : le sash se tire a la souris
        # pour agrandir/reduire chaque zone, au lieu d'un partage fixe qui laisse soit
        # le log soit l'historique trop petit selon le zoom/la taille de fenetre.
        # opaqueresize=False + couleurs en tuples : voir _build_push et PANED_BG
        self._scan_paned = PanedWindow(frame, orient="vertical", sashwidth=6, sashrelief="raised",
                                        bg=theme_color(PANED_BG), bd=0, opaqueresize=False)
        self._scan_paned.grid(row=1, column=0, sticky="nsew", pady=(5,0))

        # wrap="none" -> scrollbar horizontale interne auto : les longues lignes de
        # resultat Nmap (services + versions + OS) restent lisibles en scrollant (voir _build_push)
        self._scan_log = ctk.CTkTextbox(self._scan_paned, font=self._mono_font, wrap="none",
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
        self._install_history_resize_debounce()

    def _install_history_resize_debounce(self):
        # PERF : le CTkScrollableFrame de l'historique re-ajuste la largeur de son
        # contenu interne (via _fit_frame_dimensions_to_canvas, branche sur le
        # <Configure> de son canvas) A CHAQUE evenement de redimensionnement. Avec un
        # historique fourni, ca reflow toutes les lignes a chaque pixel de drag et
        # rendait l'onglet Scanner ~3x plus lent que les autres (mesure : ~160 ms vs
        # ~50 ms par evenement de resize). On "debounce" : pendant un drag continu on
        # debranche ce fit, et on ne le rebranche (avec un unique recalage largeur +
        # scrollregion) qu'une fois la taille stabilisee (~160 ms sans nouvel evenement).
        # -> resize fluide (~25 ms/evenement) et layout correct au repos.
        # Acces a des attributs internes de CustomTkinter (version epinglee 5.2.2) :
        # si l'implementation change, on degrade proprement (pas de debounce, aucun
        # impact fonctionnel) plutot que de planter.
        try:
            self._history_canvas = self._history_frame._parent_canvas
            self._history_fit = self._history_frame._fit_frame_dimensions_to_canvas
        except AttributeError:
            return
        self._history_fit_bound = True
        self._resize_after = None
        self._last_size = (self.winfo_width(), self.winfo_height())
        self.bind("<Configure>", self._on_window_configure, add="+")

    def _on_window_configure(self, event):
        # Ne reagit qu'au redimensionnement de la fenetre principale (pas aux
        # <Configure> d'autres widgets, ni aux simples deplacements de fenetre qui
        # emettent aussi un <Configure> mais ne changent pas la taille).
        if event.widget is not self:
            return
        size = (event.width, event.height)
        if size == self._last_size:
            return
        self._last_size = size
        if self._history_fit_bound:
            # Coupe le fit couteux pour toute la duree du drag
            self._history_canvas.unbind("<Configure>")
            self._history_fit_bound = False
        if self._resize_after is not None:
            self.after_cancel(self._resize_after)
        self._resize_after = self.after(160, self._resize_settled)

    def _resize_settled(self):
        # Fin du drag : on rebranche le fit et on applique UN seul recalage largeur +
        # scrollregion, maintenant que la taille finale est connue.
        self._resize_after = None
        if not self._history_canvas.winfo_exists():
            return
        self._history_canvas.bind("<Configure>", self._history_fit)
        self._history_fit_bound = True
        self._history_fit(None)
        self._history_canvas.configure(scrollregion=self._history_canvas.bbox("all"))

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

    def _start_scan(self):
        # Meme pattern start/stop que _start_push : pendant un scan, un nouveau clic ne
        # relance pas de thread (ce qui recreerait le bug des resultats dupliques) — il
        # demande l'arret via _scan_cancel. Contrairement au push (qui boucle sur les
        # appareils un par un), le scan Nmap est un sous-processus bloquant : on ne peut
        # pas s'arreter "entre deux hotes". _run_nmap_process contourne ca en lancant
        # nmap.exe lui-meme et en le TERMINANT (.terminate()) des que _scan_cancel est
        # pose -> l'arret est reellement immediat, pas differe a la fin du scan.
        if self._scan_running:
            self._scan_cancel.set()
            self._scan_btn.configure(state="disabled", text="Arret en cours...")
            return
        self._scan_running = True
        self._scan_cancel.clear()
        # Le bouton est deja rouge (#dc2626) au repos : on ne change que le texte.
        self._scan_btn.configure(text="Arreter le scan")
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        try:
            self._run_scan_inner()
        finally:
            self._scan_running = False
            self.after(0, lambda: self._scan_btn.configure(state="normal", text="Scanner"))

    def _run_scan_inner(self):
        # Scanne le sous-reseau saisi, affiche les resultats au fur et a mesure, sauvegarde l'historique
        box = self._scan_log
        self._clear(box)
        subnet = self._subnet_entry.get().strip()
        if not subnet:
            self._log(box, "Entrez un sous-reseau valide")
            return
        self._log(box, f"Scan de {subnet} en cours...")
        t0 = time.perf_counter()
        try:
            ports = self._ports_entry.get().strip()
            skip_discovery = bool(self._pn_var.get())
            alive = scan_network_smart(subnet, lambda m: self._log(box, m),
                                       ports=ports, skip_discovery=skip_discovery,
                                       cancel=self._scan_cancel)
            for ip, device_type in alive:
                self._log(box, f"✓ {ip} — {device_type}")
            self._log(box, f"\nTotal: {len(alive)} hotes actifs")
            self._log(box, f"Temps total du scan : {time.perf_counter() - t0:.1f}s")
            # Retire l'ancienne entree du meme sous-reseau, la remet en tete avec la date du jour
            history = load_history()
            history = [h for h in history if h["target"] != subnet]
            history.insert(0, {"target": subnet, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            save_history(history)
            self.after(0, self._load_history_ui)
        except ScanCancelled:
            # Arret demande par l'utilisateur : nmap.exe a ete termine, on n'enregistre
            # pas ce scan partiel dans l'historique.
            self._log(box, f"Scan annule par l'utilisateur (apres {time.perf_counter() - t0:.1f}s)")
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
        from netmiko import ConnectHandler  # import paresseux (voir en-tete) : ~0.4s
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
        from netmiko import ConnectHandler  # import paresseux (voir en-tete) : ~0.4s
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
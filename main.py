import customtkinter as ctk
import threading
import openpyxl
import os
import json
import subprocess
import ipaddress
import socket
from datetime import datetime
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

HISTORY_FILE = os.path.join("data", "scan_history.json")
SETTINGS_FILE = os.path.join("data", "settings.json")

def load_devices():
    wb = openpyxl.load_workbook("devices.xlsx")
    ws = wb.active
    headers = [cell.value for cell in ws[1]]
    return [dict(zip(headers, row)) for row in ws.iter_rows(min_row=2, values_only=True)]

def ping(ip):
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "500", str(ip)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return str(ip), result.returncode == 0

def detect_device(ip):
    ports = {22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}
    open_ports = []
    for port, name in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            if sock.connect_ex((ip, port)) == 0:
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
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            return json.load(f)
    return []

def save_history(history):
    os.makedirs("data", exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    return {"theme": "dark"}

def save_settings(settings):
    os.makedirs("data", exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        ctk.set_appearance_mode(self.settings.get("theme", "dark"))
        self.title("OCP Network Automation")
        self.geometry("900x650")
        self.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "ocp_logo.ico"))
        self._build()

    def _build(self):
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

        theme_label = "Mode clair" if self.settings.get("theme") == "dark" else "Mode sombre"
        self._theme_btn = ctk.CTkButton(self, text=theme_label, width=120,
                                         fg_color="gray30", hover_color="gray40",
                                         command=self._toggle_theme)
        self._theme_btn.grid(row=1, column=0, padx=16, pady=8, sticky="e")

    def _toggle_theme(self):
        current = self.settings.get("theme", "dark")
        new_theme = "light" if current == "dark" else "dark"
        self.settings["theme"] = new_theme
        save_settings(self.settings)
        ctk.set_appearance_mode(new_theme)
        self._theme_btn.configure(text="Mode clair" if new_theme == "dark" else "Mode sombre")
        self.after(100, lambda: self.geometry("900x650"))

    def _build_push(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Envoi de Configuration Multi-Appareils",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, sticky="w", pady=(5,0))
        ctk.CTkLabel(frame, text="Les commandes du fichier commands.txt sont envoyees a tous les appareils",
                     text_color="gray").grid(row=1, column=0, sticky="w")

        ctk.CTkButton(frame, text="Envoyer a tous les appareils",
                      fg_color="#1d4ed8", hover_color="#1e40af",
                      command=lambda: threading.Thread(target=self._run_push, daemon=True).start()
                      ).grid(row=0, column=1, padx=10, pady=5, sticky="e")

        self._push_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=11), state="disabled")
        self._push_log.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)

    def _build_backup(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Sauvegarde de Configuration",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, sticky="w", pady=(5,0))
        ctk.CTkLabel(frame, text="Sauvegarde la config active de tous les appareils dans des fichiers horodates",
                     text_color="gray").grid(row=1, column=0, sticky="w")

        ctk.CTkButton(frame, text="Sauvegarder tous les appareils",
                      fg_color="#15803d", hover_color="#166534",
                      command=lambda: threading.Thread(target=self._run_backup, daemon=True).start()
                      ).grid(row=0, column=1, padx=10, pady=5, sticky="e")

        self._backup_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=11), state="disabled")
        self._backup_log.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)

    def _build_scanner(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", pady=5)
        ctk.CTkLabel(top, text="Sous-reseau :").pack(side="left", padx=5)
        self._subnet_entry = ctk.CTkEntry(top, placeholder_text="192.168.1.0/24", width=200)
        self._subnet_entry.pack(side="left", padx=5)
        ctk.CTkButton(top, text="Scanner", fg_color="#dc2626", hover_color="#b91c1c",
                      command=lambda: threading.Thread(target=self._run_scan, daemon=True).start()
                      ).pack(side="left", padx=5)

        self._scan_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=11),
                                         state="disabled", height=200)
        self._scan_log.grid(row=2, column=0, sticky="nsew", pady=(5,0))

        ctk.CTkLabel(frame, text="Historique des scans",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(row=3, column=0, sticky="w", pady=(10,5))
        self._history_frame = ctk.CTkScrollableFrame(frame, height=150)
        self._history_frame.grid(row=4, column=0, sticky="ew")
        self._history_frame.grid_columnconfigure(0, weight=1)
        self._load_history_ui()

    def _load_history_ui(self):
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
            lbl.bind("<Button-1>", lambda e, t=entry["target"]: (
                self._subnet_entry.delete(0, "end"),
                self._subnet_entry.insert(0, t)
            ))
            ctk.CTkButton(row, text="x", width=30, fg_color="transparent",
                          hover_color="gray30",
                          command=lambda t=entry["target"]: self._delete_history(t)
                          ).grid(row=0, column=2, padx=5)

    def _delete_history(self, target):
        history = [h for h in load_history() if h["target"] != target]
        save_history(history)
        self._load_history_ui()

    def _run_scan(self):
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
            history = load_history()
            history = [h for h in history if h["target"] != subnet]
            history.insert(0, {"target": subnet, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            save_history(history)
            self._load_history_ui()
        except Exception as e:
            self._log(box, f"Erreur: {e}")

    def _run_push(self):
        box = self._push_log
        self._clear(box)
        devices = load_devices()
        commands = ["logging buffered 10000", "no ip http server",
                    "service timestamps log datetime msec", "ntp server 8.8.8.8"]
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
                conn.send_config_set(commands)
                conn.save_config()
                conn.disconnect()
                self._log(box, f"✓ {d['name']} — config appliquee")
            except Exception as e:
                self._log(box, f"✗ {d['name']} — {e}")

    def _run_backup(self):
        box = self._backup_log
        self._clear(box)
        devices = load_devices()
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_dir = os.path.join("backups", timestamp)
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
                output = conn.send_command("show running-config")
                conn.disconnect()
                filename = os.path.join(backup_dir, f"{d['name']}_{timestamp}.txt")
                with open(filename, "w") as f:
                    f.write(output)
                self._log(box, f"✓ {d['name']} — sauvegarde")
            except Exception as e:
                self._log(box, f"✗ {d['name']} — {e}")

    def _log(self, box, msg):
        box.configure(state="normal")
        box.insert("end", msg + "\n")
        box.see("end")
        box.configure(state="disabled")
        box.update()

    def _clear(self, box):
        box.configure(state="normal")
        box.delete("0.0", "end")
        box.configure(state="disabled")

if __name__ == "__main__":
    app = App()
    app.mainloop()
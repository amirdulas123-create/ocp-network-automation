import customtkinter as ctk
import threading
import openpyxl
import os
import subprocess
import ipaddress
from datetime import datetime
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def load_devices():
    wb = openpyxl.load_workbook("devices.xlsx")
    ws = wb.active
    headers = [cell.value for cell in ws[1]]
    return [dict(zip(headers, row)) for row in ws.iter_rows(min_row=2, values_only=True)]

def ping(ip):
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "500", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return str(ip), result.returncode == 0

def scan_network(subnet):
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())
    alive = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip, is_alive = future.result()
            if is_alive:
                alive.append(ip)
    return sorted(alive)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("OCP Network Automation")
        self.geometry("900x600")
        self.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "ocp_logo.ico"))
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        tabs = ctk.CTkTabview(self, anchor="nw")
        tabs.grid(row=0, column=0, padx=16, pady=16, sticky="nsew")
        tabs.add("Envoi Config")
        tabs.add("Sauvegarde")
        tabs.add("Scanner Réseau")
        self._build_push(tabs.tab("Envoi Config"))
        self._build_backup(tabs.tab("Sauvegarde"))
        self._build_scanner(tabs.tab("Scanner Réseau"))

    def _build_push(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        ctk.CTkButton(frame, text="Envoyer config a tous les appareils",
                      fg_color="#1d4ed8", hover_color="#1e40af",
                      command=lambda: threading.Thread(target=self._run_push, daemon=True).start()
                      ).grid(row=0, column=0, pady=10, sticky="w")
        self._push_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=11), state="disabled")
        self._push_log.grid(row=1, column=0, sticky="nsew")

    def _build_backup(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)
        ctk.CTkButton(frame, text="Sauvegarder tous les appareils",
                      fg_color="#15803d", hover_color="#166534",
                      command=lambda: threading.Thread(target=self._run_backup, daemon=True).start()
                      ).grid(row=0, column=0, pady=10, sticky="w")
        self._backup_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=11), state="disabled")
        self._backup_log.grid(row=1, column=0, sticky="nsew")

    def _build_scanner(self, frame):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", pady=10)
        ctk.CTkLabel(top, text="Sous-réseau (CIDR):").pack(side="left", padx=5)
        self._subnet_entry = ctk.CTkEntry(top, placeholder_text="192.168.1.0/24", width=200)
        self._subnet_entry.pack(side="left", padx=5)
        ctk.CTkButton(top, text="Scanner",
                      command=lambda: threading.Thread(target=self._run_scan, daemon=True).start()
                      ).pack(side="left", padx=5)
        self._scan_log = ctk.CTkTextbox(frame, font=ctk.CTkFont(family="Consolas", size=11), state="disabled")
        self._scan_log.grid(row=2, column=0, sticky="nsew")

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
                    password=d["password"], secret=d["secret"]
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
                    password=d["password"], secret=d["secret"]
                )
                conn.enable()
                output = conn.send_command("show running-config")
                conn.disconnect()
                filename = os.path.join(backup_dir, f"{d['name']}_{timestamp}.txt")
                with open(filename, "w") as f:
                    f.write(output)
                self._log(box, f"✓ {d['name']} — sauvegarde")
            except Exception as e:
                self._log(box, f"✗ {d['name']} — {e}")

    def _run_scan(self):
        box = self._scan_log
        self._clear(box)
        subnet = self._subnet_entry.get().strip()
        if not subnet:
            self._log(box, "Entrez un sous-réseau valide")
            return
        self._log(box, f"Scan de {subnet} en cours...")
        try:
            alive = scan_network(subnet)
            for ip in alive:
                self._log(box, f"✓ {ip} — en ligne")
            self._log(box, f"\nTotal: {len(alive)} hôtes actifs")
        except Exception as e:
            self._log(box, f"Erreur: {e}")

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
import tkinter as tk
from tkinter import scrolledtext
from PIL import Image, ImageTk
import openpyxl
import os
from datetime import datetime
from netmiko import ConnectHandler
import ctypes
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("OCP.NetworkAutomation")

def load_devices():
    wb = openpyxl.load_workbook("devices.xlsx")
    ws = wb.active
    headers = [cell.value for cell in ws[1]]
    return [dict(zip(headers, row)) for row in ws.iter_rows(min_row=2, values_only=True)]

def push_config():
    log.insert(tk.END, "Envoi config...\n")
    devices = load_devices()
    commands = ["logging buffered 10000", "no ip http server",
                "service timestamps log datetime msec", "ntp server 8.8.8.8"]
    for d in devices:
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
            log.insert(tk.END, f"✓ {d['name']} — config appliquée\n")
        except Exception as e:
            log.insert(tk.END, f"✗ {d['name']} — erreur: {e}\n")

def backup():
    log.insert(tk.END, "Sauvegarde...\n")
    devices = load_devices()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_dir = os.path.join("backups", timestamp)
    os.makedirs(backup_dir, exist_ok=True)
    for d in devices:
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
            log.insert(tk.END, f"✓ {d['name']} — sauvegardé\n")
        except Exception as e:
            log.insert(tk.END, f"✗ {d['name']} — erreur: {e}\n")

# Interface
root = tk.Tk()
root.iconbitmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "ocp_logo.ico"))
root.title("OCP Network Automation")
root.geometry("600x450")

# Icon taskbar
root.iconbitmap("assets/ocp_logo.ico")

# Boutons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)
tk.Button(btn_frame, text="Envoyer Config", command=push_config, bg="#1d4ed8", fg="white", width=20).pack(side="left", padx=10)
tk.Button(btn_frame, text="Sauvegarder", command=backup, bg="#15803d", fg="white", width=20).pack(side="left", padx=10)

log = scrolledtext.ScrolledText(root, height=15)
log.pack(fill="both", expand=True, padx=10, pady=10)

root.mainloop()
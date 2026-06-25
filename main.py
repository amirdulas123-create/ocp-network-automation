import openpyxl
import os
from datetime import datetime
from netmiko import ConnectHandler

# Chargement des équipements depuis Excel
wb = openpyxl.load_workbook("devices.xlsx")
ws = wb.active
headers = [cell.value for cell in ws[1]]
devices = [dict(zip(headers, row)) for row in ws.iter_rows(min_row=2, values_only=True)]

# Dossier de sauvegarde horodaté
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
backup_dir = os.path.join("backups", timestamp)
os.makedirs(backup_dir, exist_ok=True)

for d in devices:
    conn = ConnectHandler(
        device_type=d["device_type"],
        host=d["host"],
        port=int(d["port"]),
        username=d["username"],
        password=d["password"],
        secret=d["secret"]
    )
    conn.enable()
    output = conn.send_command("show running-config")
    conn.disconnect()

    filename = os.path.join(backup_dir, f"{d['name']}_{timestamp}.txt")
    with open(filename, "w") as f:
        f.write(output)
    print(f"✓ {d['name']} — sauvegarde : {filename}")

print("\nTerminé — toutes les configs sauvegardées")
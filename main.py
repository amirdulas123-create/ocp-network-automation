import openpyxl
from netmiko import ConnectHandler

# Chargement des équipements depuis Excel
wb = openpyxl.load_workbook("devices.xlsx")
ws = wb.active
headers = [cell.value for cell in ws[1]]
devices = [dict(zip(headers, row)) for row in ws.iter_rows(min_row=2, values_only=True)]

commands = [
    "logging buffered 10000",
    "no ip http server",
    "service timestamps log datetime msec",
    "ntp server 8.8.8.8"
]

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
    conn.send_config_set(commands)
    conn.save_config()
    print(f"✓ {d['name']} — config appliquée")
    conn.disconnect()

print("\nTerminé")
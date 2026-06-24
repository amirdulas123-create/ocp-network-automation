from netmiko import ConnectHandler

# Connexion à plusieurs équipements Cisco via SSH
devices = [
    {"name": "R1", "port": 5000},
    {"name": "R2", "port": 5001},
    {"name": "R3", "port": 5002},
]

for d in devices:
    device = {
        "device_type": "cisco_ios_telnet",
        "host": "127.0.0.1",
        "port": d["port"],
        "username": "admin",
        "password": "cisco",
        "secret": "cisco"
    }
    connection = ConnectHandler(**device)
    connection.enable()
    output = connection.send_command("show run | inc hostname")
    print(f"{d['name']} → {output}")
    connection.disconnect()
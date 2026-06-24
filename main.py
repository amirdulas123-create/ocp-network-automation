from netmiko import ConnectHandler

# Commandes de configuration à envoyer
commands = [
    "logging buffered 10000",
    "no ip http server",
    "service timestamps log datetime msec",
    "ntp server 8.8.8.8"
]

# Liste des équipements
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
    connection.send_config_set(commands)
    connection.save_config()
    print(f"✓ {d['name']} — configuration appliquée")
    connection.disconnect()

print("\nTerminé — config envoyée sur tous les équipements")
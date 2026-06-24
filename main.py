from netmiko import ConnectHandler

# Connexion à un équipement Cisco via SSH
cisco_01 = {
    "device_type": "cisco_ios_telnet",
    "host": "127.0.0.1",
    "port": 5000,
    "username": "admin",
    "password": "cisco",
    "secret": "cisco"
}

connection = ConnectHandler(**cisco_01)
connection.enable()
output = connection.send_command("show run | inc hostname")
print(output)
connection.disconnect()
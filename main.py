from netmiko import ConnectHandler

# Connexion à un équipement Cisco via SSH
cisco_01 = {
    "device_type": "cisco_ios",
    "host": "10.10.201.9",
    "username": "adminocp",
    "password": "ocp1920"
}

connection = ConnectHandler(**cisco_01)
output = connection.send_command("show run | inc hostname")
print(output)
connection.disconnect()
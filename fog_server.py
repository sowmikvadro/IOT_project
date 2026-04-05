import socket
import csv
import hashlib
import time
from datetime import datetime

# ---------------- CONFIG ----------------
TEMP_THRESHOLD = 35
GAS_THRESHOLD = 2500

FLOOD_THRESHOLD = 20
TIME_WINDOW = 1.0

REPLAY_WINDOW = 1.5
ALARM_HOLD_SECONDS = 10

HOST = "0.0.0.0"
PORT = 5000

NORMAL_CSV = "sensor_log.csv"
ATTACK_CSV = "attack_log.csv"
LEDGER_CSV = "ledger.csv"

VALID_DEVICES = {"ESP32"}

TRUSTED_SOURCE_IPS = {
    "ESP32": "10.194.116.102"
}

packet_tracker = {}
recent_payloads = {}
alarm_until = 0


# ---------------- HELPERS ----------------
def generate_hash(record):
    return hashlib.sha256(record.encode()).hexdigest()


def write_csv(filename, row):
    with open(filename, "a", newline="") as f:
        csv.writer(f).writerow(row)


def init_csv():
    try:
        with open(NORMAL_CSV, "x", newline="") as f:
            csv.writer(f).writerow([
                "timestamp", "temp", "gas", "hum",
                "source", "client_ip", "status"
            ])
    except FileExistsError:
        pass

    try:
        with open(ATTACK_CSV, "x", newline="") as f:
            csv.writer(f).writerow([
                "timestamp", "temp", "gas", "hum",
                "source", "client_ip", "status",
                "explanation", "record_hash"
            ])
    except FileExistsError:
        pass

    try:
        with open(LEDGER_CSV, "x", newline="") as f:
            csv.writer(f).writerow([
                "timestamp", "source", "client_ip", "record_hash"
            ])
    except FileExistsError:
        pass


def detect_threshold(temp, gas):
    reasons = []

    if temp > TEMP_THRESHOLD:
        reasons.append("FDI/Threshold Attack: Temperature threshold exceeded")

    if gas > GAS_THRESHOLD:
        reasons.append("FDI/Threshold Attack: Gas threshold exceeded")

    return reasons


def detect_flood(ip):
    current_time = time.time()

    if ip not in packet_tracker:
        packet_tracker[ip] = []

    packet_tracker[ip].append(current_time)

    packet_tracker[ip] = [
        t for t in packet_tracker[ip]
        if current_time - t <= TIME_WINDOW
    ]

    return len(packet_tracker[ip]) > FLOOD_THRESHOLD


def detect_spoofing(source, client_ip):
    reasons = []

    if source not in VALID_DEVICES:
        reasons.append("Spoofing Attack: Unauthorized device name")
        return reasons

    trusted_ip = TRUSTED_SOURCE_IPS.get(source)
    if trusted_ip and client_ip != trusted_ip:
        reasons.append("Spoofing Attack: Source/IP mismatch")

    return reasons


def detect_replay(temp, gas, hum, source, client_ip):
    now = time.time()
    payload = f"{temp},{gas},{hum},{source}"
    payload_hash = generate_hash(payload)

    if source not in recent_payloads:
        recent_payloads[source] = []

    recent_payloads[source] = [
        item for item in recent_payloads[source]
        if now - item["time"] <= REPLAY_WINDOW
    ]

    for item in recent_payloads[source]:
        if item["hash"] == payload_hash:
            return True

    recent_payloads[source].append({
        "hash": payload_hash,
        "time": now,
        "ip": client_ip
    })

    return False


def activate_alarm():
    global alarm_until
    alarm_until = time.time() + ALARM_HOLD_SECONDS


def is_alarm_active():
    return time.time() < alarm_until


# ---------------- SERVER ----------------
init_csv()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)

print(f"[+] Fog IDS Server running on {HOST}:{PORT}")

try:
    while True:
        conn, addr = server.accept()
        client_ip = addr[0]

        try:
            data = conn.recv(1024).decode(errors="ignore").strip()

            if not data:
                conn.close()
                continue

            try:
                # Expected payload format:
                # temp,gas,hum,source
                temp, gas, hum, source = data.split(",")
                temp = float(temp)
                gas = float(gas)
                hum = float(hum)
                source = source.strip()
            except Exception:
                print(f"[BAD DATA] IP: {client_ip}")
                conn.send(b"BAD_DATA\n")
                conn.close()
                continue

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            reasons = []

            # 1) FDI / Threshold
            reasons.extend(detect_threshold(temp, gas))

            # 2) TCP Flood
            if detect_flood(client_ip):
                reasons.append("TCP Flood Attack")

            # 3) Spoofing
            reasons.extend(detect_spoofing(source, client_ip))

            # 4) Replay
            if detect_replay(temp, gas, hum, source, client_ip):
                reasons.append("Replay Attack")

            if reasons:
                activate_alarm()

            if reasons:
                status = "ATTACK"
            elif source == "ESP32" and client_ip == TRUSTED_SOURCE_IPS.get("ESP32") and is_alarm_active():
                status = "ATTACK"
            else:
                status = "NORMAL"

            explanation = "; ".join(reasons) if reasons else "OK"

            # Main record hash for attack log
            record = f"{timestamp},{temp},{gas},{hum},{source},{status}"
            record_hash = generate_hash(record)

            # Ledger-specific hash for integrity verification
            ledger_record = f"{timestamp},{source},{client_ip}"
            ledger_hash = generate_hash(ledger_record)

            # Write ledger
            write_csv(LEDGER_CSV, [timestamp, source, client_ip, ledger_hash])

            if reasons:
                write_csv(ATTACK_CSV, [
                    timestamp, temp, gas, hum,
                    source, client_ip,
                    "ATTACK", explanation, record_hash
                ])
                print(f"[ATTACK] IP: {client_ip} | {explanation}")
            else:
                write_csv(NORMAL_CSV, [
                    timestamp, temp, gas, hum,
                    source, client_ip, status
                ])
                print(f"[DATA] IP: {client_ip}")

            conn.send((status + "\n").encode())

        except Exception as e:
            print(f"[ERROR] IP: {client_ip} | {e}")

        finally:
            conn.close()

except KeyboardInterrupt:
    print("\n[+] Server stopped.")
    server.close()
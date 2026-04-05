import pandas as pd
import hashlib

def generate_hash(record):
    return hashlib.sha256(record.encode()).hexdigest()

print("\n================ LOG ANALYSIS REPORT ================\n")

# ---------------- ATTACK SUMMARY ----------------
try:
    attack_df = pd.read_csv("attack_log.csv")
except FileNotFoundError:
    print("attack_log.csv not found")
    exit()

if attack_df.empty:
    print("No attacks logged yet.")
else:
    print("========== ATTACK SUMMARY ==========")
    print("Total Attacks Detected:", len(attack_df))

    print("\nAttack Types Count:")
    print(attack_df["explanation"].value_counts())

    print("\nTop Attacker IPs:")
    print(attack_df["client_ip"].value_counts().head())

    print("\nAffected Sources:")
    print(attack_df["source"].value_counts())

    print("\n========== ATTACK TIMELINE ==========")
    attack_df["timestamp"] = pd.to_datetime(attack_df["timestamp"], errors="coerce")
    attack_df = attack_df.dropna(subset=["timestamp"])
    attack_df["hour"] = attack_df["timestamp"].dt.hour

    print("\nAttacks by Hour:")
    print(attack_df["hour"].value_counts().sort_index())

# ---------------- LEDGER INTEGRITY ----------------
print("\n========== LEDGER INTEGRITY CHECK ==========")

try:
    ledger_df = pd.read_csv("ledger.csv")
except FileNotFoundError:
    print("ledger.csv not found")
    exit()

tampered = False

for i in range(len(ledger_df)):
    row_string = f"{ledger_df.iloc[i]['timestamp']},{ledger_df.iloc[i]['source']},{ledger_df.iloc[i]['client_ip']}"
    expected_hash = generate_hash(row_string)
    actual_hash = str(ledger_df.iloc[i]['record_hash']).strip()

    if expected_hash != actual_hash:
        tampered = True
        print(f"Tampering detected at row {i+1}")

if not tampered:
    print("Logs are intact. No tampering detected.")

print("\n================ END OF REPORT ================\n")
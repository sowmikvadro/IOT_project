# Fog-Based IoT Intrusion Detection System (IDS)

## Overview
This project implements a **Fog Computing-based Intrusion Detection System (IDS)** using **ESP32 and Raspberry Pi**.  
The system detects cyber attacks in real-time and performs **log-based analysis and integrity verification**.

Unlike traditional cloud-based systems, this solution processes data at the **fog layer (Raspberry Pi)**, ensuring **low latency and faster response**.

---

## Features
- Real-time intrusion detection
- Detection of multiple attack types:
  - Spoofing Attack
  - TCP Flood Attack
  - Replay Attack
  - FDI (False Data Injection)
- LED & Buzzer alert system using ESP32
- Log storage using CSV files
- Post-attack analysis (attack pattern, attacker IP, timeline)
- SHA-256 based log integrity verification

---

## System Components
- **ESP32** → Sensor node (Temperature, Gas, Humidity)
- **Raspberry Pi** → Fog IDS server
- **Python** → Server + Analysis scripts
- **WiFi Network** → Communication medium

---

## Data Format
ESP32 sends sensor data in the following format:

temp,gas,hum,ESP32

Example:
27.5,1600,45,ESP32

---

## Attack Detection

### Spoofing Attack
Detects fake identity usage when a device claims to be ESP32 but comes from an unknown IP.

### TCP Flood Attack
Detects high packet rate from a single IP within a short time window.

### Replay Attack
Detects repeated identical data packets within a short time.

### FDI (False Data Injection)
Detects abnormal sensor values:
- Temperature > 35°C
- Gas > 2500

---

## Log Files
- **sensor_log.csv** → Stores normal sensor data  
- **attack_log.csv** → Stores detected attacks with explanation  
- **ledger.csv** → Stores hash values for integrity verification  

---

## Log Analysis
The system performs post-detection analysis using `log_analysis.py`:

- Total number of attacks
- Attack type distribution
- Top attacker IP identification
- Targeted device analysis
- Time-based attack pattern (timeline)
- Log integrity verification

---

## Log Integrity Verification
- Uses **SHA-256 hashing**
- Each log entry is verified
- Detects any modification in stored logs

Example output:  
Logs are intact. No tampering detected.

---

## How to Run

### 1. Start Fog Server (Raspberry Pi)
python fog_server.py

### 2. Run ESP32
Upload Arduino code and connect to WiFi

### 3. Simulate Attacks
python replay_attack.py  
python tcp_flood.py  
python spoofing_attack.py  
python fdi_attack.py  

### 4. Run Log Analysis
python log_analysis.py

---

## Results
- Successfully detected all attack types
- Identified attacker IP
- Observed attack patterns and behavior
- Verified log integrity (no tampering detected)

---

## Key Contribution
This project not only detects attacks in real-time but also:
- Analyzes attack patterns
- Identifies attacker behavior
- Determines targeted devices
- Provides forensic insights using logs
- Ensures secure and tamper-proof logging

---

## Limitations
- Replay detection is payload-based
- No encryption (TLS not implemented)
- No machine learning model

---

## Future Improvements
- Add sequence number for stronger replay detection
- Implement ML-based anomaly detection
- Secure communication using encryption (TLS)
- Develop web dashboard for visualization

---

## Author
Sowmik Kumar Vadro  
Geeti Saha Kathi  

---

## Final Note
This project demonstrates a practical and efficient fog-based security solution for IoT systems, combining real-time detection, analysis, and integrity verification.

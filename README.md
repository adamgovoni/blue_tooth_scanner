# City of Rochester - Bluetooth Device Scanner

This project is a passive Bluetooth scanning and monitoring tool designed for **authorized city use only**.  
It detects nearby Bluetooth devices (Classic and BLE), logs detections, and provides a secure web dashboard for viewing and exporting collected data.

---

## 📡 Features

- Passive Bluetooth device discovery (Classic + BLE)
- Vendor identification (based on MAC address prefixes)
- Live device dashboard (auto-refresh)
- Secure login required for access
- Downloadable CSV log of all detections
- Logout button for session control
- Session expiration after 15 minutes of inactivity or browser close
- City of Rochester branding (login page with city logo)

---

## 🛡️ Security

- Login authentication required for all access
- Session expires automatically after 15 minutes
- Failed login attempts are logged internally (IP address + timestamp)
- All passive scanning — no device connection attempts
- Designed to respect privacy laws and passive monitoring policies

---

## 📂 Repository Structure

| Folder/File | Description |
|:---|:---|
| `scanner.py` | Main server and scanner code |
| `static/` | Contains `COR_logo.png` (City logo for login page) |
| `bluetooth_log.csv` | Generated CSV file of all logged devices |
| `mac_vendors.csv` | Optional vendor lookup table (MAC prefixes)

---

## 🚀 Setup Instructions

1. **SSH into your device (e.g., Raspberry Pi).**
2. **Install dependencies:**

   ```bash
   sudo apt update
   sudo apt install python3-pip bluetooth bluez python3-bluez
   pip3 install flask bleak

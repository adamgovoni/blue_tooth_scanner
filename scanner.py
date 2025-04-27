from flask import Flask, render_template_string, request, redirect, url_for, session, send_file
import bluetooth
from bleak import BleakScanner
import threading
import datetime
import time
import csv
import os
import asyncio
from datetime import timedelta

# ---- Flask Settings ----
app = Flask(__name__, static_folder='static')
app.secret_key = 'supersecretkey'  # Change for production!
app.permanent_session_lifetime = timedelta(minutes=15)  # Session timeout
USERNAME = 'admin'
PASSWORD = 'bluetooth123'

devices = {}
vendors = {}

SCAN_INTERVAL = 60  # Scan every 60 seconds
LOG_FILE = 'bluetooth_log.csv'
VENDOR_FILE = 'mac_vendors.csv'

# ---- Vendor Loading ----
def load_vendors():
    if os.path.exists(VENDOR_FILE):
        with open(VENDOR_FILE, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                prefix = row[0].strip().upper()
                vendor_name = row[1].strip()
                vendors[prefix] = vendor_name

def get_vendor(mac_address):
    prefix = mac_address.upper()[0:8]
    return vendors.get(prefix, "Unknown Vendor")

# ---- Logging to CSV ----
def log_to_csv(device_type, addr, vendor, name, first_seen, last_seen, hit_count, time_active, rssi):
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Type', 'MAC Address', 'Vendor', 'Name', 'First Seen', 'Last Seen', 'Hit Count', 'Time Active (minutes)', 'RSSI'])
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([device_type, addr, vendor, name, first_seen, last_seen, hit_count, time_active, rssi])

# ---- Bluetooth Scanning (Classic and BLE) ----
def scan_classic_devices():
    while True:
        try:
            nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for addr, name in nearby_devices:
                vendor = get_vendor(addr)
                if addr not in devices:
                    devices[addr] = {
                        'name': name,
                        'vendor': vendor,
                        'first_seen': now,
                        'last_seen': now,
                        'hit_count': 1,
                        'time_active': 0,
                        'rssi': 'N/A',
                        'type': 'Classic'
                    }
                    log_to_csv('Classic', addr, vendor, name, now, now, 1, 0, 'N/A')
                else:
                    devices[addr]['last_seen'] = now
                    devices[addr]['hit_count'] += 1
                    first_seen = datetime.datetime.strptime(devices[addr]['first_seen'], "%Y-%m-%d %H:%M:%S")
                    last_seen = datetime.datetime.strptime(devices[addr]['last_seen'], "%Y-%m-%d %H:%M:%S")
                    devices[addr]['time_active'] = int((last_seen - first_seen).total_seconds() / 60)
        except Exception as e:
            print(f"Classic scan error: {e}")
        time.sleep(SCAN_INTERVAL)

async def scan_ble_devices_async():
    while True:
        try:
            devices_found = await BleakScanner.discover(timeout=8.0)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for dev in devices_found:
                addr = dev.address
                name = dev.name if dev.name else 'Unknown BLE Device'
                vendor = get_vendor(addr)
                rssi = dev.rssi
                if addr not in devices:
                    devices[addr] = {
                        'name': name,
                        'vendor': vendor,
                        'first_seen': now,
                        'last_seen': now,
                        'hit_count': 1,
                        'time_active': 0,
                        'rssi': rssi,
                        'type': 'BLE'
                    }
                    log_to_csv('BLE', addr, vendor, name, now, now, 1, 0, rssi)
                else:
                    devices[addr]['last_seen'] = now
                    devices[addr]['hit_count'] += 1
                    devices[addr]['rssi'] = rssi
                    first_seen = datetime.datetime.strptime(devices[addr]['first_seen'], "%Y-%m-%d %H:%M:%S")
                    last_seen = datetime.datetime.strptime(devices[addr]['last_seen'], "%Y-%m-%d %H:%M:%S")
                    devices[addr]['time_active'] = int((last_seen - first_seen).total_seconds() / 60)
        except Exception as e:
            print(f"BLE scan error: {e}")
        await asyncio.sleep(SCAN_INTERVAL)

def scan_ble_devices():
    asyncio.run(scan_ble_devices_async())

# ---- Authentication Decorator ----
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---- HTML Pages ----
HTML_LOGIN = """..."""  # (No changes from previous login page — you can keep it.)

HTML_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>Bluetooth Surveillance Dashboard</title>
    <meta http-equiv="refresh" content="15">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #111; color: #eee; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #555; padding: 8px; text-align: left; }
        th { background-color: #333; }
        tr.classic { background-color: #222; }
        tr.ble { background-color: #003366; }
        h1 { text-align: center; }
        .centered { text-align: center; }
        .button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 24px;
            margin: 10px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <h1>Nearby Bluetooth Devices</h1>
    <div class="centered">
        <form action="/download" style="display:inline;">
            <button class="button" type="submit">Download Logs</button>
        </form>
        <form action="/logout" style="display:inline;">
            <button class="button" type="submit" style="background-color: #f44336;">Logout</button>
        </form>
    </div>
    <table>
        <tr>
            <th>Type</th>
            <th>Name</th>
            <th>Vendor</th>
            <th>MAC Address</th>
            <th>First Seen</th>
            <th>Last Seen</th>
            <th>Hit Count</th>
            <th>Time Active (minutes)</th>
            <th>RSSI</th>
        </tr>
        {% for mac, info in devices.items() %}
        <tr class="{{ info.type|lower }}">
            <td>{{ info.type }}</td>
            <td>{{ info.name }}</td>
            <td>{{ info.vendor }}</td>
            <td>{{ mac }}</td>
            <td>{{ info.first_seen }}</td>
            <td>{{ info.last_seen }}</td>
            <td>{{ info.hit_count }}</td>
            <td>{{ info.time_active }}</td>
            <td style="color: 
                {% if info.rssi != 'N/A' %}
                    {% if info.rssi > -60 %}
                        lightgreen
                    {% elif info.rssi > -80 %}
                        yellow
                    {% else %}
                        red
                    {% endif %}
                {% else %}
                    white
                {% endif %}
            ">{{ info.rssi }}</td>
        </tr>
        {% endfor %}
    </table>
    <p style="text-align: center; margin-top: 30px; color: #aaa;">Authorized Use Only - City of Rochester</p>
</body>
</html>
"""

# ---- Flask Routes ----
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_attempt = request.form['username']
        password_attempt = request.form['password']
        if username_attempt == USERNAME and password_attempt == PASSWORD:
            session.permanent = False
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            attempt_ip = request.remote_addr
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"⚠️ Failed login attempt from IP {attempt_ip} at {now} with username: {username_attempt}")
    return HTML_LOGIN

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template_string(HTML_DASHBOARD, devices=devices)

@app.route('/download')
@login_required
def download():
    return send_file(LOG_FILE, as_attachment=True)

# ---- Main Execution ----
if __name__ == "__main__":
    load_vendors()
    classic_thread = threading.Thread(target=scan_classic_devices, daemon=True)
    ble_thread = threading.Thread(target=scan_ble_devices, daemon=True)
    classic_thread.start()
    ble_thread.start()
    app.run(host='0.0.0.0', port=5000)

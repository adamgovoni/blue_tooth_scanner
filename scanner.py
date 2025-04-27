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
app.secret_key = 'supersecretkey'  # Change this for production!
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
HTML_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>Bluetooth Surveillance Dashboard</title>
    <meta http-equiv="refresh" content="15">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f0f2f5;
            color: #222;
        }
        header {
            background-color: #003366;
            padding: 20px;
            text-align: center;
            color: white;
        }
        h1 {
            margin: 0;
            font-size: 2em;
        }
        .centered {
            text-align: center;
            margin: 20px 0;
        }
        .button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 24px;
            margin: 5px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            text-decoration: none;
        }
        .button.logout {
            background-color: #f44336;
        }
        .dashboard-container {
            max-width: 1200px;
            margin: 20px auto;
            padding: 20px;
            background-color: white;
            border-radius: 12px;
            box-shadow: 0px 0px 10px rgba(0,0,0,0.2);
        }
        .scroll-table {
            max-height: 600px;
            overflow-y: auto;
            border: 1px solid #ccc;
            border-radius: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ccc;
        }
        th {
            background-color: #003366;
            color: white;
            position: sticky;
            top: 0;
            z-index: 2;
        }
        tr.classic {
            background-color: #f9f9f9;
        }
        tr.ble {
            background-color: #e6f0ff;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>

<header>
    <h1>Nearby Bluetooth Devices</h1>
</header>

<div class="centered">
    <form action="/download" style="display:inline;">
        <button class="button" type="submit">Download Logs</button>
    </form>
    <form action="/logout" style="display:inline;">
        <button class="button logout" type="submit">Logout</button>
    </form>
</div>

<div class="dashboard-container">
    <div class="scroll-table">
        <table>
            <thead>
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
            </thead>
            <tbody>
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
                                orange
                            {% else %}
                                red
                            {% endif %}
                        {% else %}
                            gray
                        {% endif %}
                    ">{{ info.rssi }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<div class="footer">
    Authorized Use Only - City of Rochester
</div>

</body>
</html>
"""

HTML_LOGIN = """
<!DOCTYPE html>
<html>
<head>
    <title>Login - City of Rochester</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #1a1a1a;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            color: #eee;
        }
        .login-box {
            background-color: #2c2c2c;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0px 0px 15px #000;
            text-align: center;
            width: 300px;
        }
        .logo {
            width: 150px;
            margin-bottom: 20px;
        }
        input[type=text], input[type=password] {
            width: 100%;
            padding: 10px;
            margin: 10px 0 20px 0;
            display: inline-block;
            border: none;
            background: #3d3d3d;
            color: #fff;
            border-radius: 5px;
        }
        input[type=submit] {
            background-color: #4CAF50;
            color: white;
            padding: 10px;
            width: 100%;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        input[type=submit]:hover {
            background-color: #45a049;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <img src="/static/COR_logo.png" class="logo" alt="City of Rochester Logo">
        <h2>Authorized Access Only</h2>
        <form method="POST">
            <input name="username" type="text" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <input type="submit" value="Login">
        </form>
        <div class="footer">
            Property of City of Rochester
        </div>
    </div>
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

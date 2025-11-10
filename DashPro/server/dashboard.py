from flask import Flask, render_template, jsonify
import sqlite3, os
from datetime import datetime
import pytz

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database.db")


LOCAL_TZ = pytz.timezone("America/New_York")  

def to_local_time(iso_time):
    try:
        utc_time = datetime.fromisoformat(iso_time)
        local_time = utc_time.astimezone(LOCAL_TZ)
        return local_time.strftime("%m/%d/%Y %I:%M%p")
    except Exception:
        return iso_time


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

print("📂 Using database path:", DB_PATH)

def fetch_reports():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT 
            id, flag_count, last_flag_type, last_flag_file, device_id, hostname, user,
            os, os_version, architecture, ip, mac, cpu_usage_percent, cpu_cores,
            total_memory_gb, used_memory_gb, memory_usage_percent, status, uptime,
            timestamp, last_seen
        FROM reports
        ORDER BY timestamp DESC
    """)

    rows = c.fetchall()
    conn.close()

    reports = []
    for row in rows:
        reports.append({
            "id": row["id"],
            "flag_count": row["flag_count"],
            "last_flag_type": row["last_flag_type"],
            "last_flag_file": row["last_flag_file"],
            "device_id": row["device_id"],
            "hostname": row["hostname"],
            "user": row["user"],
            "os": row["os"],
            "os_version": row["os_version"],
            "architecture": row["architecture"],
            "ip": row["ip"],
            "mac": row["mac"],
            "cpu_usage_percent": row["cpu_usage_percent"],
            "cpu_cores": row["cpu_cores"],
            "total_memory_gb": row["total_memory_gb"],
            "used_memory_gb": row["used_memory_gb"],
            "memory_usage_percent": row["memory_usage_percent"],
            "uptime": row["uptime"],
            "status": row["status"],
            "timestamp": row["timestamp"],
            "last_seen": to_local_time(row["last_seen"]),

        })

    return reports


@app.route('/')
def index():
    reports = fetch_reports()
    return render_template('index.html', reports=reports)

if __name__ == '__main__':
    app.run(debug=True, port=5000)


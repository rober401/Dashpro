from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
import sqlite3
import json
import os
from datetime import datetime, timedelta
import threading, time
import pytz


app = FastAPI()
LOCAL_TZ = pytz.timezone("America/New_York")  # or your timezone


# ✅ Centralize your DB path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'database.db')
print(f"[API] Using database file: {DB_PATH}")

# ✅ All database columns (besides id)
FIELDS = [
    "flag_count", "last_flag_type", "last_flag_file",  # ✅ ADDED
    "device_id", "hostname", "user", "os", "os_version", "architecture",
    "ip", "mac", "cpu_usage_percent", "cpu_cores", "total_memory_gb",
    "used_memory_gb", "memory_usage_percent", "status", "uptime",
    "timestamp", "last_seen"
]



def to_local_time(iso_time):
    try:
        utc_time = datetime.fromisoformat(iso_time)
        local_time = utc_time.astimezone(LOCAL_TZ)
        return local_time.strftime("%m/%d/%Y %I:%M%p")
    except Exception:
        return iso_time

# ✅ Thread: background monitor for offline devices
def check_device_status():
    print("API:     Started watching device status...")
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            cutoff = datetime.now() - timedelta(minutes=1)

            c.execute("SELECT id, last_seen FROM reports")
            rows = c.fetchall()

            for id_, last_seen in rows:
                if not last_seen:
                    continue
                try:
                    last_dt = datetime.fromisoformat(last_seen)  # ✅ Works now that last_seen is ISO
                    if last_dt < cutoff:
                        c.execute("UPDATE reports SET status = ? WHERE id = ?", ("offline", id_))
                    else:
                        c.execute("UPDATE reports SET status = ? WHERE id = ?", ("online", id_))
                except ValueError:
                    print(f"[WARN] Invalid last_seen format for ID {id_}")

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ERROR] Device watcher failed: {e}")
        time.sleep(60)  # run every 60 seconds

# ✅ Create / ensure database table matches your fields
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            hostname TEXT,
            user TEXT,
            os TEXT,
            os_version TEXT,
            architecture TEXT,
            ip TEXT,
            mac TEXT,
            cpu_usage_percent REAL,
            cpu_cores INTEGER,
            total_memory_gb REAL,
            used_memory_gb REAL,
            memory_usage_percent REAL,
            status TEXT,
            uptime TEXT,
            timestamp TEXT,
            last_seen TEXT,
            flag_count INTEGER DEFAULT 0,
            last_flag_type TEXT,
            last_flag_file TEXT
        )
    """)
    conn.commit()
    conn.close()

@app.on_event("startup")
def startup_event():
    init_db()
    device_watcher = threading.Thread(target=check_device_status, daemon=True)
    device_watcher.start()

@app.post("/api/alert")
async def receive_alert(request: Request, authorization: str = Header(None)):
    data = await request.json()
    print(json.dumps(data, indent=2))

    if authorization != "Bearer 3f91a2d4a77b2e9a437b25f2acfe99405df2c1cb9e07a94f3f5d1df5d7f8e6b8":
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    device_id = data.get("device_id")
    flag_type = data.get("status", "THREAT")
    file_path = data.get("file_path", "Unknown")
    timestamp = datetime.now().strftime("%I:%M %p")

    if not device_id:
        return JSONResponse(status_code=400, content={"error": "Missing device_id"})

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Check if device exists
    c.execute("SELECT flag_count FROM reports WHERE device_id = ?", (device_id,))
    result = c.fetchone()

    if result:
        current_flags = int(result[0]) if result[0] else 0
        new_flags = current_flags + 1

        c.execute("""
            UPDATE reports
            SET flag_count = ?, last_flag_type = ?, last_flag_file = ?, timestamp = ?
            WHERE device_id = ?
        """, (new_flags, flag_type, file_path, timestamp, device_id))
        conn.commit()
        print(f"[ALERT] Device {device_id} flagged: {file_path} ({flag_type})")
    else:
        print(f"[ALERT] Unknown device {device_id} — could not update flags.")

    conn.close()
    return JSONResponse({"message": "Alert processed", "status": "ok"})

@app.post("/api/heartbeat")
async def receive_data(request: Request, authorization: str = Header(None)):
    """Receives system info from client and updates or inserts records."""
    data = await request.json()
    print(json.dumps(data, indent=2))

    # ✅ Auth check
    if authorization != "Bearer 3f91a2d4a77b2e9a437b25f2acfe99405df2c1cb9e07a94f3f5d1df5d7f8e6b8":
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    # ✅ Validate required field
    device_id = data.get("device_id")
    if not device_id:
        return JSONResponse(status_code=400, content={"error": "Missing device_id"})

    # ✅ Prepare timestamps
    last_seen_iso = datetime.now().isoformat()  # ✅ FIXED for watcher
    now_display = datetime.now().strftime("%m/%d/%Y %I:%M%p").lstrip("0").replace(" 0", " ")


    # ✅ Fill defaults for missing fields
    values = []
    for field in FIELDS:
        if field == "timestamp":
            values.append(now_display)
        elif field == "last_seen":
            values.append(last_seen_iso)  # ✅ FIXED
        else:
            values.append(data.get(field, None))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ✅ Check if this device exists
    c.execute("SELECT id FROM reports WHERE device_id = ?", (device_id,))
    existing = c.fetchone()

    if existing:
        # ✅ Update dynamically
        update_clause = ", ".join([f"{f} = ?" for f in FIELDS if f != "device_id"])
        c.execute(f"""
            UPDATE reports
            SET {update_clause}
            WHERE device_id = ?
        """, [data.get(f, None) if f not in ("timestamp", "last_seen") else
              (now_display if f == "timestamp" else last_seen_iso)
              for f in FIELDS if f != "device_id"] + [device_id])
        action = "updated"
    else:
        # 🆕 Insert dynamically
        placeholders = ", ".join(["?"] * len(FIELDS))
        columns = ", ".join(FIELDS)
        c.execute(f"""
            INSERT INTO reports ({columns})
            VALUES ({placeholders})
        """, values)
        action = "inserted"

    conn.commit()
    conn.close()

    return {"status": "success", "message": f"Device {action}"}

# Run standalone
if __name__ == "__main__":
    init_db()

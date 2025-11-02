import platform
import socket
import uuid, time
import psutil
import os
from datetime import datetime

flags = 0 # May be faulted as client will start with infection


# Path to store the unique device ID (so it persists)
DEVICE_ID_FILE = os.path.join(os.path.dirname(__file__), "device_id.txt")

# New Script Email Detection Threat

def get_system_uptime():
    """Return system uptime as a formatted string (e.g., '3h 42m 17s')."""
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time

    hours, remainder = divmod(int(uptime_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s"

def get_device_id():
    """
    Load or generate a unique device ID that persists across reboots.
    """
    try:
        if os.path.exists(DEVICE_ID_FILE):
            with open(DEVICE_ID_FILE, "r") as f:
                return f.read().strip()
        else:
            new_id = str(uuid.uuid4())
            with open(DEVICE_ID_FILE, "w") as f:
                f.write(new_id)
            return new_id
    except Exception as e:
        # Fallback to hostname if something goes wrong
        print("Failed to generate unique device id: {}".format(e))
        return socket.gethostname()


def get_system_info():
    try:
        # Get Hostname
        hostname = socket.gethostname()
        try:
            user = psutil.users()[0].name if psutil.users() else "Unknown"
        except Exception:
            user = "Unknown/Error"

        # OS Info
        os_name = platform.system()
        os_version = platform.version()
        os_arch = platform.architecture()[0]
        os_release = platform.release()

        # Network Info
        ip_address = socket.gethostbyname(hostname)
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                                for ele in range(0, 8 * 6, 8)][::-1])

        # CPU Info
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_cores = psutil.cpu_count(logical=False)

        # Memory Info
        memory = psutil.virtual_memory()
        total_memory_gb = round(memory.total / (1024 ** 3), 2)
        used_memory_gb = round(memory.used / (1024 ** 3), 2)
        memory_percent = memory.percent

        # Timestamp
        now = datetime.now()
        timestamp = now.strftime("%I:%M %p")

        # ✅ Include the persistent device_id
        return {
            "flags": flags,
            "device_id": get_device_id(),
            "hostname": hostname,
            "user": user,
            "os": f"{os_name} {os_release}",
            "os_version": os_version,
            "architecture": os_arch,
            "ip": ip_address,
            "mac": mac_address,
            "cpu_usage_percent": cpu_percent,
            "cpu_cores": cpu_cores,
            "total_memory_gb": total_memory_gb,
            "used_memory_gb": used_memory_gb,
            "memory_usage_percent": memory_percent,
            "uptime": get_system_uptime(),  # ✅ Add this line
            "timestamp": timestamp,
            "status": "online"
        }

    except Exception as e:
        return {"error": str(e)}

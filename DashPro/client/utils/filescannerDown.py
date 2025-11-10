from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os, glob
import subprocess

# Global callback (set later by client)
alert_callback = None


def scan_file(path):
    if not os.path.exists(path):
        return "UNKNOWN"

    possibles = []
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    possibles.append(os.path.join(pf, "Windows Defender", "MpCmdRun.exe"))
    possibles.append(os.path.join(pf, "Microsoft Defender", "MpCmdRun.exe"))
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    possibles.extend(glob.glob(os.path.join(pd, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")))
    mpcmd = next((p for p in possibles if os.path.isfile(p)), None)

    if not mpcmd:
        return "UNKNOWN"

    try:
        proc = subprocess.run(
            [mpcmd, "-Scan", "-ScanType", "3", "-File", path],
            capture_output=True, text=True, timeout=30
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        text = out.lower()

        if "no threats" in text or "no threats were detected" in text or "threats found: 0" in text:
            #return f"SAFE {path}"
        ############################################################
            if alert_callback:  
                alert_callback(path, "TEST_NOT_A_THREAT")
            return f"TEST_NOT_A_THREAT {path}"
        ############################################################

        elif "detected" in text or "threat" in text or "quarantined" in text:
            if alert_callback:  
                alert_callback(path, "THREAT")
            return f"THREAT {path}"

        else:
            return f"UNKNOWN {path}"

    except subprocess.TimeoutExpired:
        return f"TIMEOUT {path}"


DOWNLOAD_DIR = os.path.join(os.path.expanduser("~"), "Downloads")


class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"New file downloaded: {event.src_path}")
            print(scan_file(event.src_path))


def main(callback=None):
    """Start watching the Downloads folder."""
    global alert_callback
    alert_callback = callback 

    event_handler = DownloadHandler()
    observer = Observer()
    observer.schedule(event_handler, DOWNLOAD_DIR, recursive=False)
    observer.start()
    print(f"Monitoring downloads in: {DOWNLOAD_DIR}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()  # runs standalone if executed directly


import os
import sys
import time
import ctypes
import threading
import win32file
import win32con

# ---------------------------------------------
# 🧱  Manual constants for compatibility
# ---------------------------------------------
FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5

# ---------------------------------------------
# ⚙️  Ensure admin privileges
# ---------------------------------------------
def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("🔒 Restarting with admin privileges...")
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            raise SystemExit
    except Exception as e:
        print(f"⚠️ Admin check failed: {e}")

# ---------------------------------------------
# 🗂️  Paths to monitor (user-focused)
# ---------------------------------------------
def get_watch_paths():
    user = os.path.expanduser("~")
    folders = [
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "Documents"),
        os.path.join(os.getenv("LOCALAPPDATA", ""), "Temp"),
        os.path.join(os.getenv("APPDATA", "")),
    ]
    folders.append("C:\\")  # Optionally include root drive
    return [p for p in folders if os.path.exists(p)]

# ---------------------------------------------
# 🧠  Logger
# ---------------------------------------------
def log_download(path):
    with open("file_creation_log.txt", "a", encoding="utf-8") as f:
        f.write(f"[{time.ctime()}] {path}\n")

# ---------------------------------------------
# 👀  Watcher logic
# ---------------------------------------------
def watch_path(path):
    print(f"👁️  Watching: {path}")
    while True:
        try:
            handle = win32file.CreateFile(
                path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ
                | win32con.FILE_SHARE_WRITE
                | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )

            notify_flags = win32con.FILE_NOTIFY_CHANGE_FILE_NAME | win32con.FILE_NOTIFY_CHANGE_SIZE

            while True:
                try:
                    results = win32file.ReadDirectoryChangesW(
                        handle,
                        8192,  # Larger buffer
                        True,  # Recursive
                        notify_flags,
                        None,
                        None,
                    )

                    for action, filename in results:
                        full_path = os.path.join(path, filename)
                        if action == FILE_ACTION_ADDED:
                            print(f"New file created: {full_path}")
                            log_download(full_path)

                except Exception as e:
                    print(f"⚠Watcher error at {path}: {e}")
                    time.sleep(1)
                    break  # Recreate handle

        except Exception as e:
            print(f"Failed to watch {path}: {e}")
            time.sleep(5)

# ---------------------------------------------
# 🚀  Main
# ---------------------------------------------
if __name__ == "__main__":
    ensure_admin()
    watch_paths = get_watch_paths()

    for p in watch_paths:
        threading.Thread(target=watch_path, args=(p,), daemon=True).start()

    print("\nSystem-wide file creation monitor running...")
    print("Logging to: file_creation_log.txt\n")

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nExiting watcher.")

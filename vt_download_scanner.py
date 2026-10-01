"""
VirusTotal Download Scanner
Watches your Downloads folder, scans every new file on VirusTotal,
and shows a toast that disappears after a few seconds.

Install:  pip install watchdog requests
Run:      python vt_download_scanner.py
"""
import os
import sys
import time
import queue
import hashlib
import threading
import tkinter as tk
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ----------------------------- Settings -----------------------------
API_KEY = os.environ.get("VT_API_KEY", "PUT_YOUR_API_KEY_HERE")
# (folder, recursive)  -> recursive=True also watches every sub-folder inside it
WATCH_DIRS = [
    (Path.home() / "Downloads", True),
    (Path.home() / "Desktop", True),
    # (Path(r"D:\MyFolder"), False),
]
UPLOAD_UNKNOWN = True      # False = hash lookup only (nothing is ever uploaded)
TOAST_SECONDS = 6          # how long the toast stays (danger stays longer)
MAX_WAIT_MINUTES = 10      # max time to wait for a new analysis
IGNORE_EXT = {".crdownload", ".tmp", ".part", ".download", ".partial", ".opdownload", ".lnk"}
# --------------------------------------------------------------------

BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}
MB = 1024 * 1024

ui_queue = queue.Queue()
seen = set()
seen_lock = threading.Lock()


# ----------------------------- VirusTotal ---------------------------
def vt_get(path):
    """GET with simple retry on rate limit (free API = 4 requests/min)."""
    for _ in range(6):
        r = requests.get(BASE + path, headers=HEADERS, timeout=60)
        if r.status_code == 429:
            time.sleep(30)
            continue
        return r
    return r


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_until_stable(path, timeout=120):
    """Wait until the file stops growing and can be opened."""
    last = -1
    end = time.time() + timeout
    while time.time() < end:
        try:
            size = path.stat().st_size
            with open(path, "rb"):
                pass
            if size == last and size > 0:
                return True
            last = size
        except OSError:
            pass
        time.sleep(1.5)
    return False


def upload_and_wait(path):
    size = path.stat().st_size
    url = BASE + "/files"
    if size > 32 * MB:
        r = vt_get("/files/upload_url")
        r.raise_for_status()
        url = r.json()["data"]
    with open(path, "rb") as f:
        r = requests.post(url, headers=HEADERS, files={"file": (path.name, f)}, timeout=900)
    r.raise_for_status()
    analysis_id = r.json()["data"]["id"]

    deadline = time.time() + MAX_WAIT_MINUTES * 60
    while time.time() < deadline:
        time.sleep(15)
        r = vt_get(f"/analyses/{analysis_id}")
        if r.status_code != 200:
            continue
        attrs = r.json()["data"]["attributes"]
        if attrs.get("status") == "completed":
            return attrs["stats"]
    return None


def scan(path):
    """Returns the stats dict, or None if unknown / not finished."""
    r = vt_get(f"/files/{sha256_of(path)}")
    if r.status_code == 200:
        stats = r.json()["data"]["attributes"].get("last_analysis_stats")
        if stats:
            return stats
    elif r.status_code != 404:
        r.raise_for_status()
    if not UPLOAD_UNKNOWN:
        return None
    return upload_and_wait(path)


def verdict(stats):
    if stats is None:
        return "warn", "Not analysed", "VirusTotal has no result for this file yet."
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
    if mal >= 3:
        return "bad", "Dangerous - don't open it", f"{mal} / {total} engines flagged it as malicious."
    if mal > 0 or sus > 0:
        return "warn", "Suspicious", f"{mal} malicious, {sus} suspicious out of {total} engines. Be careful."
    return "safe", "Safe", f"0 / {total} engines flagged this file."


def process(path):
    key = str(path)
    try:
        if not wait_until_stable(path):
            return
        print(f"[+] Scanning {path.name}")
        ui_queue.put(("info", "Scanning... (new files can take a few minutes)", path.name, 600))
        level, title, detail = verdict(scan(path))
        ui_queue.put((level, title, f"{path.name}\n{detail}", 10 if level == "bad" else TOAST_SECONDS))
    except Exception as e:
        print(f"[!] Error: {e}")
        ui_queue.put(("warn", "Scan failed", f"{path.name}\n{e}", 10))
    finally:
        with seen_lock:
            seen.discard(key)


# ------------------------------- Toast UI ---------------------------
class Toast:
    COLORS = {"safe": "#2ecc71", "warn": "#f39c12", "bad": "#e74c3c", "info": "#3498db"}
    ICONS = {"safe": "✔", "warn": "!", "bad": "✖", "info": "…"}
    BG = "#1e1f26"

    def __init__(self, root):
        self.root = root
        self.win = None
        self.job = None

    def close(self, *_):
        if self.job:
            try:
                self.root.after_cancel(self.job)
            except tk.TclError:
                pass
            self.job = None
        if self.win:
            try:
                self.win.destroy()
            except tk.TclError:
                pass
            self.win = None

    def fade(self, w, start, end, step, done=None):
        a = start

        def tick():
            nonlocal a
            if w is not self.win:
                return
            a += step
            try:
                if (step > 0 and a >= end) or (step < 0 and a <= end):
                    w.attributes("-alpha", end)
                    if done:
                        done()
                    return
                w.attributes("-alpha", a)
                w.after(20, tick)
            except tk.TclError:
                pass

        tick()

    def show(self, level, title, detail, seconds):
        self.close()
        color = self.COLORS[level]
        w = tk.Toplevel(self.root)
        self.win = w
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        w.attributes("-alpha", 0.0)

        frame = tk.Frame(w, bg=self.BG)
        frame.pack(fill="both", expand=True)
        tk.Frame(frame, bg=color, width=8).pack(side="left", fill="y")
        body = tk.Frame(frame, bg=self.BG)
        body.pack(side="left", padx=16, pady=12)
        tk.Label(body, text=f"{self.ICONS[level]}  {title}", font=("Segoe UI", 13, "bold"),
                 fg=color, bg=self.BG, anchor="w").pack(anchor="w")
        tk.Label(body, text=detail, font=("Segoe UI", 10), fg="#d8dae0", bg=self.BG,
                 justify="left", anchor="w", wraplength=330).pack(anchor="w", pady=(4, 0))

        w.update_idletasks()
        width = max(w.winfo_reqwidth(), 360)
        height = w.winfo_reqheight()
        x = w.winfo_screenwidth() - width - 24
        y = w.winfo_screenheight() - height - 70
        w.geometry(f"{width}x{height}+{x}+{y}")

        def bind_all_children(widget):
            widget.bind("<Button-1>", self.close)
            for c in widget.winfo_children():
                bind_all_children(c)

        bind_all_children(w)

        self.fade(w, 0.0, 0.96, 0.08)
        self.job = self.root.after(
            int(seconds * 1000),
            lambda: self.fade(w, 0.96, 0.0, -0.06, self.close),
        )


# ------------------------------ Watcher -----------------------------
class Handler(FileSystemEventHandler):
    def __init__(self, pool):
        self.pool = pool

    def on_created(self, event):
        self.handle(event.src_path, event.is_directory)

    def on_moved(self, event):  # browsers rename .crdownload -> final file
        self.handle(event.dest_path, event.is_directory)

    def handle(self, p, is_dir):
        path = Path(p)
        if is_dir or path.suffix.lower() in IGNORE_EXT:
            return
        if path.name.startswith("~") or path.name.lower() == "desktop.ini":
            return
        if path.resolve() == Path(__file__).resolve():
            return
        with seen_lock:
            if p in seen:
                return
            seen.add(p)
        self.pool.submit(process, path)


def main():
    if API_KEY == "PUT_YOUR_API_KEY_HERE":
        print("Set your VirusTotal API key first (VT_API_KEY env var or API_KEY in the script).")
        return
    # optional: python vt_download_scanner.py "D:\Games" "E:\Work"  (recursive)
    if len(sys.argv) > 1:
        targets = [(Path(a), True) for a in sys.argv[1:]]
    else:
        targets = WATCH_DIRS
    targets = [(d, r) for d, r in targets if d.is_dir()]
    if not targets:
        print("No valid folders to watch.")
        return

    root = tk.Tk()
    root.withdraw()
    toast = Toast(root)

    pool = ThreadPoolExecutor(max_workers=2)
    observer = Observer()
    for d, rec in targets:
        observer.schedule(Handler(pool), str(d), recursive=rec)
    observer.start()
    print("Watching:", ", ".join(str(d) for d, _ in targets), " (Ctrl+C to stop)")

    def poll():
        try:
            while True:
                toast.show(*ui_queue.get_nowait())
        except queue.Empty:
            pass
        root.after(200, poll)

    root.after(200, poll)
    toast.show("info", "Scanner running", f"Watching {len(targets)} folder(s)", 3)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()

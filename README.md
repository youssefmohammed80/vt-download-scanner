# VT Download Scanner

A small Python tool that watches your folders (Downloads, Desktop, or any path you choose), sends every new file to [VirusTotal](https://www.virustotal.com), and shows a clean pop-up notification with the verdict. The notification fades out on its own after a few seconds.

> **Safe** ✔ · **Suspicious** ! · **Dangerous** ✖

---

## Features

- Automatically scans every new file that appears in the watched folders
- Works with any folder, including all of its sub-folders
- Checks the file's SHA-256 hash first, so known files are answered in seconds and **nothing is uploaded**
- Uploads unknown files and waits for the analysis (can be turned off for privacy)
- Colour-coded toast notification that auto-hides, and can be dismissed with a click
- Ignores temporary browser downloads (`.crdownload`, `.part`, ...) and waits until the file has finished downloading
- Can start automatically every time you log in to Windows

---

## How it works

```
New file appears
      │
      ▼
Wait until the file finishes downloading
      │
      ▼
Calculate SHA-256  ──►  Ask VirusTotal about this hash
                              │
              ┌───────────────┴────────────────┐
         Known file                      Unknown file
              │                                │
              │                    Upload it (if enabled) and wait
              │                                │
              └───────────────┬────────────────┘
                              ▼
                  Show the verdict as a toast
```

### Verdicts

| Colour | Title | Rule |
|--------|-------|------|
| 🟢 Green | Safe | 0 engines flagged the file |
| 🟠 Orange | Suspicious | 1–2 malicious detections, or any "suspicious" detection |
| 🔴 Red | Dangerous | 3 or more engines flagged it as malicious |

A low number of detections can be a false positive. Open the file's page on VirusTotal and check **which** engines flagged it before deciding.

You can change the threshold in the `verdict()` function (`mal >= 3`).

---

## Requirements

- Python 3.8 or newer
- A free VirusTotal account (for the API key)
- Windows is the tested platform. The `watchdog` and `tkinter` libraries are cross-platform, so Linux and macOS should work too, but they are untested.

---

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/<your-username>/<repo-name>.git
   cd <repo-name>
   ```

2. **Install the dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   (`tkinter` ships with Python on Windows, so there is nothing extra to install.)

3. **Add your VirusTotal API key** (see the next section)

4. **Run it**

   ```bash
   python vt_download_scanner.py
   ```

   You will see a "Scanner running" notification. Download any file and wait for the result.

---

## How to get a VirusTotal API key

The key is free and takes about a minute.

1. Go to [virustotal.com](https://www.virustotal.com) and click **Sign up** (or sign in).
2. Click your **profile icon** in the top-right corner.
3. Choose **API Key**.
4. Copy the key (a 64-character string).

### Where to put the key

**Option A (recommended): environment variable**

Open PowerShell and run:

```powershell
setx VT_API_KEY "your_api_key_here"
```

Close PowerShell, open a new one, and run the script. The script reads the key automatically, so you never have to write it inside the code.

**Option B: edit the script**

Open `vt_download_scanner.py` and replace the placeholder:

```python
API_KEY = os.environ.get("VT_API_KEY", "PUT_YOUR_API_KEY_HERE")
```

with your key between the quotes.

> ⚠️ **Never commit your API key to GitHub.** Anyone who has it can use up your quota. If you used Option B, remove the key before pushing. If it leaks, go back to your VirusTotal profile and regenerate it.

### Free API limits

| Limit | Value |
|-------|-------|
| Requests per minute | 4 |
| Requests per day | 500 |
| Max upload size | 650 MB |

The script waits and retries automatically when it hits the rate limit. The free API is intended for personal, non-commercial use.

---

## Configuration

All settings are at the top of `vt_download_scanner.py`.

```python
WATCH_DIRS = [
    (Path.home() / "Downloads", True),   # True = include sub-folders
    (Path.home() / "Desktop", True),
    # (Path(r"D:\MyFolder"), False),     # False = this folder only
]
UPLOAD_UNKNOWN = True    # False = hash lookup only, nothing is uploaded
TOAST_SECONDS = 6        # how long the notification stays on screen
MAX_WAIT_MINUTES = 10    # max time to wait for a new analysis
```

You can also pass folders on the command line without editing the file (they are watched recursively):

```bash
python vt_download_scanner.py "D:\Games" "E:\Work"
```

---

## Run automatically at Windows startup

You need the scanner to run every time you turn on your PC. Use `pythonw.exe` instead of `python.exe`, so it runs in the background without a console window.

### Step 0: set your API key as an environment variable

Use **Option A** above (`setx VT_API_KEY ...`). Programs started at login will pick it up.

### Step 1: find your `pythonw.exe` path

```powershell
where python
```

Take the folder it prints and use `pythonw.exe` in the same folder. For example:

```
C:\Users\<you>\AppData\Local\Programs\Python\Python313\pythonw.exe
```

### Method 1: Startup folder (simplest)

1. Press `Win + R`, type `shell:startup`, and press Enter.
2. Right-click inside the folder and choose **New → Shortcut**.
3. In the **location** box, paste (adjust both paths):

   ```
   "C:\Users\<you>\AppData\Local\Programs\Python\Python313\pythonw.exe" "C:\path\to\vt_download_scanner.py"
   ```

4. Name it `VT Download Scanner` and finish.

To remove it later, delete the shortcut from the same folder.

### Method 2: Task Scheduler

Run this once in PowerShell (adjust both paths):

```powershell
schtasks /Create /TN "VT Download Scanner" /SC ONLOGON /RL LIMITED /TR "\"C:\Users\<you>\AppData\Local\Programs\Python\Python313\pythonw.exe\" \"C:\path\to\vt_download_scanner.py\""
```

To remove it:

```powershell
schtasks /Delete /TN "VT Download Scanner" /F
```

### Check that it works / stop it

- Restart your PC. After sign-in you should see the "Scanner running" notification.
- Because it runs without a window, stop it from **Task Manager → Details → `pythonw.exe` → End task**.

---

## Privacy notes

- **Files that VirusTotal has never seen are uploaded**, and uploaded files can be accessed by VirusTotal's partners and security researchers. Do not use the upload mode with personal, confidential, or work documents.
- Set `UPLOAD_UNKNOWN = False` to only look up hashes. Nothing leaves your PC except the hash, but unknown files will show "Not analysed".
- Only watch folders that actually receive downloads. Avoid watching an entire drive.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'requests'` | Run `python -m pip install -r requirements.txt` using the same Python you run the script with |
| "Set your VirusTotal API key first" | The key is missing. Check the environment variable (open a **new** terminal after `setx`) or the `API_KEY` line |
| Notification says `Scan failed ... 401` | The API key is wrong or has extra spaces |
| "Scanning..." stays for a long time | The file is new to VirusTotal. Analysis can take a few minutes. Large files and a busy queue take longer |
| Many files in a row are slow | The free API allows 4 requests per minute. Results arrive one after another |
| Unzipping an archive triggers lots of scans | Every extracted file is scanned. Exclude that folder or use hash-only mode |
| Nothing happens when I download | Make sure the download folder is in `WATCH_DIRS` and the console shows `Watching: ...` |

---

## Limitations

- Only files created or moved into a watched folder are scanned. Existing files are not scanned.
- Files larger than 650 MB cannot be uploaded to VirusTotal.
- An antivirus verdict is not a guarantee. A "Safe" result means the engines did not flag the file, not that it is harmless.
- Password-protected archives cannot be inspected by the engines.

---

## Disclaimer

This tool is provided as-is, for personal use. Use it as one extra layer of protection, not as a replacement for a real antivirus and careful habits. The author is not affiliated with VirusTotal.

---

## License

Released under the MIT License. Add a `LICENSE` file to the repository if you want to publish it under these terms.

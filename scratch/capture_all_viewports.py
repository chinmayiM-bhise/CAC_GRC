import subprocess
import os

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
BASE_URL = "http://127.0.0.1:8000/dashboard"

viewports = [
    ("1920x1080", 1920, 1080),
    ("1600x900",  1600, 900),
    ("1366x768",  1366, 768),
    ("1280x720",  1280, 720),
    ("1024x768",  1024, 768)
]

os.makedirs("scratch/screenshots", exist_ok=True)

print("[*] Capturing screenshots across viewports...")

for name, w, h in viewports:
    # Controls View
    out_ctrl = os.path.abspath(f"scratch/screenshots/controls_{name}.png")
    cmd = [
        CHROME,
        "--headless=new",
        f"--window-size={w},{h}",
        f"--screenshot={out_ctrl}",
        f"{BASE_URL}#controls"
    ]
    subprocess.run(cmd, check=True)
    size_ctrl = os.path.getsize(out_ctrl)
    print(f"  [+] Captured Controls at {name}: {size_ctrl:,} bytes -> {out_ctrl}")

    # Mappings View
    out_map = os.path.abspath(f"scratch/screenshots/mappings_{name}.png")
    cmd = [
        CHROME,
        "--headless=new",
        f"--window-size={w},{h}",
        f"--screenshot={out_map}",
        f"{BASE_URL}#mappings"
    ]
    subprocess.run(cmd, check=True)
    size_map = os.path.getsize(out_map)
    print(f"  [+] Captured Mappings at {name}: {size_map:,} bytes -> {out_map}")

# Overview, Evidence, Findings at 1280x720
for view in ["overview", "evidence", "findings", "chaos"]:
    out_v = os.path.abspath(f"scratch/screenshots/{view}_1280x720.png")
    cmd = [
        CHROME,
        "--headless=new",
        "--window-size=1280,720",
        f"--screenshot={out_v}",
        f"{BASE_URL}#{view}"
    ]
    subprocess.run(cmd, check=True)
    print(f"  [+] Captured {view} at 1280x720: {os.path.getsize(out_v):,} bytes -> {out_v}")

print("\n[SUCCESS] All screenshots captured successfully!")

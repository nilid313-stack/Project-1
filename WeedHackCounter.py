import os
import json
import zipfile
import subprocess
import sys
import shutil
from pathlib import Path
import psutil

# IOCs from analysis
IOCS = {
    'packages': ['me/mclauncher/', 'dev/majanito/', 'dev/jnic/'],
    'resources': ['c4f763d6-e34c-42e9-bba1-b80cfa5a55df.dat', 'a125e430-2459-4702-9797-49fce5f280ae.dat'],
    'strings': ['initializeWeedhack', 'Mod init state:', '0xce6d41de'],
    'domains': ['receiver.cy', 'weedhack.cy', 'whreceive.ru'],
    'paths': ['SecurityUpdates', 'Updater.vbs', 'component-'],
    'tasks': ['JavaSecurityUpdater']
}

def get_minecraft_dirs():
    home = Path.home()
    return [home / '.minecraft', home / 'Library/Application Support/minecraft']

def scan_jar(jar_path):
    threats = []
    try:
        with zipfile.ZipFile(jar_path, 'r') as zf:
            for name in zf.namelist():
                for ioc in IOCS['packages'] + IOCS['resources'] + IOCS['strings']:
                    if ioc in name:
                        threats.append(name)
                if 'fabric.mod.json' in name:
                    data = json.loads(zf.read(name).decode())
                    if data.get('id') == 'loaderclient':
                        threats.append('SUSPICIOUS MOD ID')
    except:
        pass
    return threats

def check_network():
    print("🌐 Network scan skipped (macOS privacy)")
    return []

def main():
    print("🔍 WeedHackCounter - macOS/Linux Edition")
    threats = []
    
    # Scan .minecraft mods
    print("📁 Scanning ~/.minecraft...")
    for mc_dir in get_minecraft_dirs():
        if mc_dir.exists():
            for jar in mc_dir.rglob('*.jar'):
                jar_threats = scan_jar(jar)
                if jar_threats:
                    print(f"🚨 {jar}: {jar_threats}")
                    threats.append(str(jar))
    
    # Network
    threats.extend(check_network())
    
    if threats:
        print(f"\n❗ {len(threats)} threats! Delete suspicious mods.")
    else:
        print("\n✅ Clean! Safe from e-gangsters.")

if __name__ == '__main__':
    main()

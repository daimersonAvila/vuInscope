"""Load demo records (only when the registry is empty). Usage: python scripts/seed.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from vulnscope.config import Settings
from vulnscope.bootstrap import build_container

EXAMPLES = [
    ("Log4Shell: remote code execution in Log4j", "CVE-2021-44228", "critica", "abierta", 10.0),
    ("Heartbleed: memory leak in OpenSSL", "CVE-2014-0160", "alta", "mitigada", 7.5),
    ("Shellshock in Bash", "CVE-2014-6271", "critica", "cerrada", 9.8),
    ("SQL injection in login form", "CVE-2023-12345", "alta", "en_revision", 8.1),
    ("HTTP header exposes server version", "CVE-2022-0001", "baja", "abierta", 3.1),
    ("Reflected XSS in search box", "CVE-2023-0456", "media", "abierta", 6.1),
]
c = build_container(Settings.from_env(), ai_client=None)
if c.registry.list():
    print("Registry already has data; nothing loaded.")
else:
    for t, i, s, e, p in EXAMPLES:
        c.registry.create({"titulo": t, "cve_codigo": i, "severidad": s, "estado": e, "puntaje_cvss": p})
        # give the Markov chain some real history
    print(f"Loaded {len(EXAMPLES)} records.")

"""Print a salted hash for ADMIN_PASSWORD_HASH. Usage: python scripts/hash_password.py"""
import getpass
from werkzeug.security import generate_password_hash

pw = getpass.getpass("New admin password (min 12 chars): ")
if len(pw) < 12:
    raise SystemExit("Password too short.")
print(generate_password_hash(pw))

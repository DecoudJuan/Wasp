import subprocess
import hashlib


def run(user_cmd):
    # Vulnerable: inyección de comandos (OWASP A03 / CWE-78).
    return subprocess.call(user_cmd, shell=True)


def hash_password(password):
    # Vulnerable: hash débil para contraseñas (OWASP A02 / CWE-327).
    return hashlib.md5(password.encode()).hexdigest()

# adaptive_hash_selector.py
import os
import bcrypt
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

passwords = [
    b"12345",
    b"correcthorsebatterystaple",
    b"averylongpasswordthatgoesbeyondbcryptslimitsoitisnottruncatedearlyandsecure",
    b"admin",
    b"pass1234"
]

argon2id = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)

def choose_algorithm(pw: bytes):
    if len(pw) < 8:
        return "argon2id"  # Best for weak/short passwords
    elif len(pw) > 72:
        return "argon2id"  # bcrypt truncates at 72B
    elif pw.isalnum():
        return "scrypt"     # Likely predictable - use memory hard
    else:
        return "bcrypt"

def hash_password(pw: bytes):
    algo = choose_algorithm(pw)
    if algo == "bcrypt":
        return "bcrypt", bcrypt.hashpw(pw, bcrypt.gensalt())
    elif algo == "scrypt":
        return "scrypt", hashlib.scrypt(pw, salt=os.urandom(16), n=2**14, r=8, p=1)
    elif algo == "argon2id":
        return "argon2id", argon2id.hash(pw.decode())


def verify_password(pw: bytes, hashed, algo: str):
    if algo == "bcrypt":
        return bcrypt.checkpw(pw, hashed)
    elif algo == "scrypt":
        try:
            return hashed == hashlib.scrypt(pw, salt=hashed[:16], n=2**14, r=8, p=1)
        except Exception:
            return False
    elif algo == "argon2id":
        try:
            return argon2id.verify(hashed, pw.decode())
        except VerifyMismatchError:
            return False

if __name__ == "__main__":
    print(f"{'Password':<60} {'Algorithm':<10} {'Hash Sample (truncated)'}")
    print("=" * 100)
    for pw in passwords:
        algo, hsh = hash_password(pw)
        print(f"{pw.decode():<60} {algo:<10} {str(hsh)[:40]}...")

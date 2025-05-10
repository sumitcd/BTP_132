import time
import hashlib
import bcrypt
import argon2
import os
import threading

# Global config
weak_passwords = [b"123", b"password", b"admin"]
strong_password = b"Sup3r$ecretP@ss!"

argon2_hasher = argon2.PasswordHasher()

# Brute Force Simulation
def brute_force_sim(hash_func, test_pass_list):
    print(f"\n[+] Brute Force Attack on {hash_func.__name__}")
    target_hash = hash_func(test_pass_list[-1])
    start = time.time()
    for p in test_pass_list:
        if hash_func(p) == target_hash:
            break
    end = time.time()
    print(f"  Time to crack (simulated): {end - start:.4f} seconds")

# Misconfiguration Tests
def pbkdf2_weak(password):
    return hashlib.pbkdf2_hmac('sha256', password, b'salt', 1000)

def bcrypt_weak(password):
    return bcrypt.hashpw(password, bcrypt.gensalt(rounds=4))

def scrypt_weak(password):
    return hashlib.scrypt(password, salt=b'salt', n=2**12, r=4, p=1)

def argon2_weak(password):
    hasher = argon2.PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    return hasher.hash(password.decode())

# Thread Stress Test
def thread_stress_test(hash_func, label):
    print(f"\n[+] Concurrency Stress Test for {label}")
    def worker():
        for _ in range(5):
            hash_func(str(os.urandom(8)).encode())

    threads = [threading.Thread(target=worker) for _ in range(20)]
    start = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    end = time.time()
    print(f"  Time with 20 threads: {end - start:.2f} seconds")

# Standard Hash Functions
def hash_pbkdf2(password=strong_password):
    return hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 100000)

def hash_bcrypt(password=strong_password):
    return bcrypt.hashpw(password, bcrypt.gensalt())

def hash_scrypt(password=strong_password):
    return hashlib.scrypt(password, salt=os.urandom(16), n=2**14, r=8, p=1)

def hash_argon2(password=strong_password):
    return argon2_hasher.hash(password.decode())

# Run Tests
def run_vulnerability_tests():
    print("\n=== Brute Force Simulations ===")
    for hash_func in [hash_pbkdf2, hash_bcrypt, hash_scrypt, hash_argon2]:
        brute_force_sim(hash_func, weak_passwords)

    print("\n=== Misconfiguration Weaknesses ===")
    for label, func in [("PBKDF2 (weak)", pbkdf2_weak),
                        ("bcrypt (weak)", bcrypt_weak),
                        ("scrypt (weak)", scrypt_weak),
                        ("Argon2 (weak)", argon2_weak)]:
        start = time.time()
        func(strong_password)
        end = time.time()
        print(f"{label:<20} completed in {end - start:.4f} seconds")

    print("\n=== Concurrency Stress Tests ===")
    thread_stress_test(hash_pbkdf2, "PBKDF2")
    thread_stress_test(hash_bcrypt, "bcrypt")
    thread_stress_test(hash_scrypt, "scrypt")
    thread_stress_test(hash_argon2, "Argon2")

if __name__ == '__main__':
    run_vulnerability_tests()

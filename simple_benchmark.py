import timeit
import bcrypt
import hashlib
import argon2
import os
import memory_profiler
import matplotlib.pyplot as plt

password = b"strongpassword123"

# Hashing functions
def hash_bcrypt():
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password, salt)

def hash_pbkdf2():
    return hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 100000)

def hash_scrypt():
    return hashlib.scrypt(password, salt=os.urandom(16), n=16384, r=8, p=1)

argon2_hasher = argon2.PasswordHasher()

def hash_argon2():
    return argon2_hasher.hash(password.decode())

# Benchmark execution time
def benchmark(func, num_runs=100):
    return timeit.timeit(func, number=num_runs) / num_runs

# Memory profiling
def get_memory_usage(func):
    mem_usage = memory_profiler.memory_usage(func, max_usage=True)
    return mem_usage if isinstance(mem_usage, float) else mem_usage[0]

if __name__ == '__main__':
    print("Benchmarking password hashing algorithms...\n")

    bcrypt_time = benchmark(hash_bcrypt)
    pbkdf2_time = benchmark(hash_pbkdf2)
    scrypt_time = benchmark(hash_scrypt)
    argon2_time = benchmark(hash_argon2)

    bcrypt_memory = get_memory_usage(hash_bcrypt)
    pbkdf2_memory = get_memory_usage(hash_pbkdf2)
    scrypt_memory = get_memory_usage(hash_scrypt)
    argon2_memory = get_memory_usage(hash_argon2)

    # Print results
    print(f"{'Algorithm':<15} {'Time (s)':<15} {'Memory (MB)':<15}")
    print("=" * 40)
    print(f"{'bcrypt':<15} {bcrypt_time:<15.6f} {bcrypt_memory:<15.2f}")
    print(f"{'PBKDF2':<15} {pbkdf2_time:<15.6f} {pbkdf2_memory:<15.2f}")
    print(f"{'scrypt':<15} {scrypt_time:<15.6f} {scrypt_memory:<15.2f}")
    print(f"{'Argon2':<15} {argon2_time:<15.6f} {argon2_memory:<15.2f}")
        
    # Visualization
    labels = ['bcrypt', 'PBKDF2', 'scrypt', 'Argon2']
    times = [bcrypt_time, pbkdf2_time, scrypt_time, argon2_time]
    memory = [bcrypt_memory, pbkdf2_memory, scrypt_memory, argon2_memory]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Execution Time Plot
    axes[0].bar(labels, times, color=['blue', 'green', 'red', 'purple'])
    axes[0].set_ylabel("Time (seconds)")
    axes[0].set_title("Execution Time Comparison")

    # Memory Usage Plot
    axes[1].bar(labels, memory, color=['blue', 'green', 'red', 'purple'])
    axes[1].set_ylabel("Memory (MB)")
    axes[1].set_title("Memory Usage Comparison")

    plt.tight_layout()
    plt.show()
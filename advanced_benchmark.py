import time
import memory_profiler
import bcrypt
import hashlib
import argon2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
import matplotlib.pyplot as plt
import numpy as np

NUM_TRIALS = 5

# Sample password to hash
PASSWORD = b"securepassword123"
SALT = b"16byteslongsalt!!"  # 16-byte salt for bcrypt

def hash_bcrypt():
    """Hash password using bcrypt"""
    return bcrypt.hashpw(PASSWORD, bcrypt.gensalt())

def hash_pbkdf2():
    """Hash password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    return urlsafe_b64encode(kdf.derive(PASSWORD))

def hash_scrypt():
    """Hash password using scrypt"""
    return hashlib.scrypt(PASSWORD, salt=SALT, n=16384, r=8, p=1)

def hash_argon2():
    """Hash password using Argon2"""
    ph = argon2.PasswordHasher()
    return ph.hash(PASSWORD.decode())

def benchmark_algorithm(func):
    """Measure execution time of a function"""
    start_time = time.perf_counter()
    func()
    end_time = time.perf_counter()
    return end_time - start_time

def get_memory_usage(func):
    """Measure memory usage of a function"""
    mem_usage = memory_profiler.memory_usage((func,), max_usage=True)
    return mem_usage

# Plot Results
def plot_results(results):
    """Plots execution time and memory usage for password hashing algorithms."""
    algorithms, times, memory = zip(*results)

    x = np.arange(len(algorithms))
    width = 0.4  # Bar width

    fig, ax1 = plt.subplots(figsize=(9, 5))
    
    # Plot execution time
    ax1.bar(x - width/2, times, width, label="Time (s)", color="royalblue")
    ax1.set_ylabel("Time (s)")
    ax1.set_xlabel("Algorithm")
    ax1.set_title("Password Hashing Benchmark")
    ax1.set_xticks(x)
    ax1.set_xticklabels(algorithms)
    ax1.grid(axis="y", linestyle="--", alpha=0.6)

    # Plot memory usage on secondary Y-axis
    ax2 = ax1.twinx()
    ax2.bar(x + width/2, memory, width, label="Memory (MB)", color="orangered", alpha=0.7)
    ax2.set_ylabel("Memory (MB)")

    # Adjust legends and layout
    ax1.legend(loc="upper left", bbox_to_anchor=(0, 1.15))  # Move the legend above the plot
    ax2.legend(loc="upper right", bbox_to_anchor=(1, 1.15))  # Move the second legend above the plot
    fig.tight_layout(pad=2)  # Add padding to avoid overlap

    plt.show()

if __name__ == "__main__":
    trials = NUM_TRIALS  # Number of times each algorithm is benchmarked
    print(f"Benchmarking password hashing algorithms ({trials} trials per algorithm)...\n")

    algo_params = {
        "bcrypt": {
            "Cost Factor (Rounds)": "12 (Controls computational cost; higher is slower but more secure)",
            "Salt Length": "16 bytes (Prevents rainbow table attacks)"
        },
        "PBKDF2": {
            "Iterations": "100,000 (More iterations increase security but slow hashing)",
            "Salt Length": "16 bytes (Ensures hash uniqueness)",
            "Hash Algorithm": "SHA-256 (Used to derive the key)"
        },
        "scrypt": {
            "N (Cost Factor)": "16384 (Determines CPU/memory cost, higher is more secure)",
            "r (Block Size)": "8 (Affects memory usage and parallelization)",
            "p (Parallelization)": "1 (Controls parallel execution)",
            "Salt Length": "16 bytes (Prevents hash collisions)"
        },
        "Argon2": {
            "Time Cost": "2 (Number of iterations for hashing)",
            "Memory Cost": "102400 KB (Amount of memory required, making attacks harder)",
            "Parallelism": "8 (Threads used for faster computation)",
            "Salt Length": "16 bytes (Ensures unique hashes)"
        }
    }
    results = []

    for algo, func in [
        ("bcrypt", hash_bcrypt),
        ("PBKDF2", hash_pbkdf2),
        ("scrypt", hash_scrypt),
        ("Argon2", hash_argon2),
    ]:
        print(f"{algo} parameters:")
        for param, value in algo_params[algo].items():
            print(f"  - {param}: {value}")

        exec_times = [benchmark_algorithm(func) for _ in range(trials)]
        mem_usages = [get_memory_usage(func) for _ in range(trials)]

        avg_time = sum(exec_times) / trials
        avg_memory = sum(mem_usages) / trials

        results.append((algo, avg_time, avg_memory))
        print("{:<15} {:<15} {:<15}".format("\nAlgorithm", "Time (s)", "Memory (MB)"))
        print("=" * 40)
        print(f"{algo:<15} {avg_time:<15.6f} {avg_memory:<15.2f}\n")
    
    plot_results(results)
    print("\nBenchmarking complete.")
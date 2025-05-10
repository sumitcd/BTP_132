# 🔐 HASHING ALGORITHMS BENCHMARK
-------------------------------

## 📦 Dependencies

- All required packages are listed in `requirements.txt`.

## 💻 HOW TO RUN (IN WINDOWS)

### 1. Using a Virtual Environment (Recommended)

Once you have cloned the git repository, open the terminal in the project folder.

```bash
python -m venv [your_venv_name]
```

**For first-time setup:**

```bash
[your_venv_name]\Scripts\activate
pip install -r requirements.txt
python .\simple_benchmark.py
# or
python .\advanced_benchmark.py
```

**For subsequent use:**

```bash
[your_venv_name]\Scripts\activate
python .\simple_benchmark.py
# or
python .\advanced_benchmark.py
```

### 2. Without Virtual Environment (Using requirements.txt directly)

Once you have cloned the git repository, open the terminal in the project folder.

```bash
pip install -r requirements.txt
# For simple benchmark
python simple_benchmark.py
# For advanced benchmark
python advanced_benchmark.py
```

---

# 🔍 Password Hashing Vulnerability Simulator

This module demonstrates the security implications of password hashing strategies by simulating brute-force attacks, evaluating misconfigurations, and performing multithreaded stress tests on common hash functions.

## 📋 Features

- **Brute Force Attack Simulation**: Tests how fast weak passwords can be matched against a hash using various secure algorithms.
- **Misconfiguration Testing**: Demonstrates how insecure settings (like low iteration counts or memory usage) weaken secure algorithms.
- **Concurrency Stress Testing**: Evaluates how well each hashing function handles multithreaded environments.

## 🧪 Tested Hash Functions

- PBKDF2 (HMAC-SHA256)
- bcrypt
- scrypt
- Argon2

## ⚙️ Additional Requirements

Install extra dependencies via pip:

```bash
pip install bcrypt argon2-cffi
```

## 🚀 How to Run

Execute the test script:

```bash
python password_hashing_test.py
```

This will output:
- Brute force simulation results for several hash functions.
- Timing benchmarks for weak configurations.
- Performance under multithreaded stress.

## ⚠️ Disclaimer

This script is **for educational and demonstration purposes only**. It shows how improper configurations can severely degrade the security of password hashing methods. **Do not use these insecure configurations in production.**

---

# 🤖 Adaptive Hash Algorithm Selector

This script (`adaptive_hash_selector.py`) selects the best password hashing algorithm dynamically based on password characteristics, simulating an adaptive security model.

## ✅ Features

- Automatically selects between:
  - **bcrypt** (for general secure use)
  - **scrypt** (for alphanumeric/predictable passwords)
  - **argon2id** (for short/weak or long passwords)
- Hashes and verifies passwords using the chosen algorithm
- Protects against common password handling pitfalls (e.g. bcrypt truncation)

## 🚀 How to Run

```bash
python adaptive_hash_selector.py
```

Expected output:

- Passwords tested
- Selected algorithm
- Truncated sample of the resulting hash

## 🔧 Logic for Algorithm Selection

- **argon2id**: For short passwords (<8 bytes) or very long ones (>72 bytes)
- **scrypt**: For predictable/alphanumeric passwords
- **bcrypt**: Default fallback for general use

## ⚠️ Notes

- bcrypt truncates passwords longer than 72 bytes.
- Make sure passwords passed to Argon2 are UTF-8 decodable.
- All hashing methods include secure salts.

---

## 📄 License

This project is released under the MIT License.

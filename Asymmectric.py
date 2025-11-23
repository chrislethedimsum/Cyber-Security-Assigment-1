import time, os, gc, statistics, resource
import psutil
import pandas as pd
import matplotlib.pyplot as plt

# Crypto libraries
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


# ========== GLOBAL SETTINGS ==========
ITERATIONS = 1000
RESULT_DIR = "results"
CSV_PATH = f"{RESULT_DIR}/asymmetric_results.csv"

os.makedirs(RESULT_DIR, exist_ok=True)


# ========== LOAD TOP100 PASSWORDS ==========
def load_top100(path="top100.txt"):
    if not os.path.exists(path):
        raise FileNotFoundError("Missing top100.txt")
    with open(path, "r", encoding="latin-1") as f:
        words = [w.strip().encode("utf8", errors="ignore") for w in f if w.strip()]
    return words


# ========== MEASUREMENT WRAPPER ==========
def measure(func, iterations=ITERATIONS):
    # Reset environment
    gc.collect()
    process = psutil.Process(os.getpid())

    # Capture CPU + RSS before
    cpu_before = process.cpu_times()

    # Reset OS peak RSS baseline
    _ = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    start = time.perf_counter()

    for i in range(iterations):
        func(i)
        if (i + 1) % (iterations // 10) == 0:
            print(f"  progress: {i+1}/{iterations}")

    end = time.perf_counter()

    # After measurements
    cpu_after = process.cpu_times()
    cpu_used = (cpu_after.user - cpu_before.user) + (cpu_after.system - cpu_before.system)

    # True peak RSS
    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Convert peak memory to kilobytes (KB)
    if peak_kb < 10_000:  # macOS returns bytes (small number)
        peak_kb = peak_kb / 1024  # Convert bytes to KB
    else:  # Linux returns KiB, so we need to divide by 1024
        peak_kb = peak_kb  # Already in KB, no conversion needed
    wall = end - start
    return wall, cpu_used, peak_kb


# ========== BENCHMARK FUNCTIONS ==========
def rsa_keygen(_):
    RSA.generate(1024)

def rsa_sign_verify(i, passwords):
    pw = passwords[i % len(passwords)]
    key = RSA.generate(1024)
    pub = key.publickey()
    h = SHA256.new(pw)
    sig = pkcs1_15.new(key).sign(h)
    pkcs1_15.new(pub).verify(h, sig)

def ecc_keygen(_):
    ECC.generate(curve="P-256")

def ecc_sign_verify(i, passwords):
    pw = passwords[i % len(passwords)]
    key = ECC.generate(curve="P-256")
    h = SHA256.new(pw)
    sig = DSS.new(key, "fips-186-3").sign(h)
    DSS.new(key.public_key(), "fips-186-3").verify(h, sig)

def dsa_keygen(_):
    DSA.generate(1024)

def dsa_sign_verify(i, passwords):
    pw = passwords[i % len(passwords)]
    key = DSA.generate(1024)
    h = SHA256.new(pw)
    sig = DSS.new(key, "fips-186-3").sign(h)
    DSS.new(key.public_key(), "fips-186-3").verify(h, sig)

print("Generating DH (2048-bit) parameters… may take 5–20s")
dh_params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
print("DH parameters ready.")

def dh_exchange(_):
    priv1 = dh_params.generate_private_key()
    priv2 = dh_params.generate_private_key()
    shared1 = priv1.exchange(priv2.public_key())
    shared2 = priv2.exchange(priv1.public_key())
    assert shared1 == shared2


# ========== RUN ALL TESTS ==========
def run():
    passwords = load_top100()

    tests = [
        ("RSA-1024-keygen", lambda i: rsa_keygen(i)),
        ("RSA-1024-sign_verify", lambda i: rsa_sign_verify(i, passwords)),
        ("ECC-P256-keygen", lambda i: ecc_keygen(i)),
        ("ECC-P256-sign_verify", lambda i: ecc_sign_verify(i, passwords)),
        ("DSA-1024-keygen", lambda i: dsa_keygen(i)),
        ("DSA-1024-sign_verify", lambda i: dsa_sign_verify(i, passwords)),
        ("DH-2048-exchange", lambda i: dh_exchange(i)),
    ]

    rows = []
    for name, fn in tests:
        print(f"\n=== Running {name} ===")
        wall, cpu, mem = measure(fn)
        print(f"Done {name}: wall={wall:.4f}s cpu={cpu:.4f}s peakRSS={mem} bytes")

        rows.append({
            "algorithm": name,
            "wall_time_s": wall,
            "cpu_time_s": cpu,
            "memory_peak_bytes": mem,
            "iterations": ITERATIONS,
            "per_iter_ms": (wall / ITERATIONS) * 1000,
        })

    df = pd.DataFrame(rows)
    df.to_csv(CSV_PATH, index=False)

    print("\n=== FINAL BENCHMARK SUMMARY ===")
    print(df.to_string(index=False))

    # ======== PLOTS ========
    plt.figure(figsize=(12, 5))
    plt.bar(df["algorithm"], df["wall_time_s"])
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Seconds")
    plt.title("Asymmetric Algorithms — Wall Time")
    plt.tight_layout()
    plt.savefig(f"{RESULT_DIR}/asymmetric_time.png", dpi=150)
    plt.close()

    plt.figure(figsize=(12, 5))
    plt.bar(df["algorithm"], df["cpu_time_s"])
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("CPU Seconds")
    plt.title("Asymmetric Algorithms — CPU Time")
    plt.tight_layout()
    plt.savefig(f"{RESULT_DIR}/asymmetric_cpu.png", dpi=150)
    plt.close()

    plt.figure(figsize=(12, 5))
    plt.bar(df["algorithm"], df["memory_peak_bytes"])
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Peak RSS (KB)") 
    plt.title("Asymmetric Algorithms — Memory Usage (M1)")
    plt.tight_layout()
    plt.savefig(f"{RESULT_DIR}/asymmetric_memory.png", dpi=150)
    plt.close()

    print("\nSaved:")
    print(f" CSV  → {CSV_PATH}")
    print(f" Graphs → {RESULT_DIR}/asymmetric_*.png\n")


if __name__ == "__main__":
    run()

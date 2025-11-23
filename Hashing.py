import time, os, gc, statistics, resource
import psutil
import pandas as pd
import hashlib
import matplotlib.pyplot as plt

# ========== GLOBAL SETTINGS ==========
ITERATIONS = 10000
RESULT_DIR = "results"
CSV_PATH = f"{RESULT_DIR}/hash_results.csv"

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
def md5_hash(i, passwords):
    pw = passwords[i % len(passwords)]
    h = hashlib.md5(pw)
    h.digest()

def sha1_hash(i, passwords):
    pw = passwords[i % len(passwords)]
    h = hashlib.sha1(pw)
    h.digest()

def sha256_hash(i, passwords):
    pw = passwords[i % len(passwords)]
    h = hashlib.sha256(pw)
    h.digest()

def sha512_hash(i, passwords):
    pw = passwords[i % len(passwords)]
    h = hashlib.sha512(pw)
    h.digest()


# ========== RUN ALL TESTS ==========
def run():
    passwords = load_top100()

    tests = [
        ("MD5-hash", lambda i: md5_hash(i, passwords)),
        ("SHA-1-hash", lambda i: sha1_hash(i, passwords)),
        ("SHA-256-hash", lambda i: sha256_hash(i, passwords)),
        ("SHA-512-hash", lambda i: sha512_hash(i, passwords)),
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
    plt.title("Hashing Algorithms — Wall Time")
    plt.tight_layout()
    plt.savefig(f"{RESULT_DIR}/hash_time.png", dpi=150)
    plt.close()

    plt.figure(figsize=(12, 5))
    plt.bar(df["algorithm"], df["cpu_time_s"])
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("CPU Seconds")
    plt.title("Hashing Algorithms — CPU Time")
    plt.tight_layout()
    plt.savefig(f"{RESULT_DIR}/hash_cpu.png", dpi=150)
    plt.close()

    plt.figure(figsize=(12, 5))
    plt.bar(df["algorithm"], df["memory_peak_kb"])
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Peak RSS (KB)") 
    plt.title("Hashing Algorithms — Memory Usage (M1)")
    plt.tight_layout()
    plt.savefig(f"{RESULT_DIR}/hash_memory.png", dpi=150)
    plt.close()

    print("\nSaved:")
    print(f" CSV  → {CSV_PATH}")
    print(f" Graphs → {RESULT_DIR}/hash_*.png\n")


if __name__ == "__main__":
    run()

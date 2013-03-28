import timeit

HASHES = [
    ("pyblake2", "blake2b"),
    ("pyblake2", "blake2s"),
    ("hashlib",  "md5"),
    ("hashlib",  "sha1"),
    ("hashlib",  "sha256"),
    ("hashlib",  "sha512"),
]

SIZES = [64, 128, 1024, 2047, 2048, 1000000]

SETUP_CODE = """
from {mod} import {fn} as hasher
data = b'x'*{size}
"""

BENCH_CODE = """
h = hasher()
h.update(data)
h.digest()
"""

def measure(mod, fn, size):
    num = 10
    best = min(timeit.repeat(BENCH_CODE,
                SETUP_CODE.format(mod=mod, fn=fn, size=size),
                number=num, repeat=5))
    return num * (size/1024./1024.) / best

def main():
    for size in SIZES:
        print("{0} bytes\n".format(size))
        for mod, fn in HASHES:
            mbs = measure(mod, fn, size)
            print(" {0}.{1}    \t   {2:3.0f} MB/s".format(mod, fn, mbs))
        print("")

if __name__ == "__main__":
    main()

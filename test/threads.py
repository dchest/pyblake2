"""
Simple script to see if GIL is released when hashing.
"Threaded" benchmark should be ~2x as fast as sequential
if it is, but only on a multicore CPU.
"""

import hashlib, threading, time
from pyblake2 import blake2b

class Hasher(threading.Thread):
    def __init__(self, hashfn):
        threading.Thread.__init__(self)
        self.hashfn = hashfn
        self.setDaemon(True)
        self.start()
        
    def run(self):
        md = self.hashfn()
        buf = b'a'*1024*1024
        for i in range(1000):
            md.update(buf)
        print(md.hexdigest())

def sequential(hashfn):
    md = hashfn()
    buf = b'a'*1024*1024
    for i in range(1000):
        md.update(buf)
    print(md.hexdigest())

print("pyblake2:")

t = time.time()
for i in range(2):
    sequential(blake2b)
print("blake2b (sequential) {0}".format(time.time() - t))

t = time.time()
threads = [Hasher(blake2b) for i in range(2)]
for thread in threads:
    thread.join()
print("blake2b (threaded) {0}".format(time.time() - t))

print("\nhashlib:")

t = time.time()
for i in range(2):
    sequential(hashlib.sha1)
print("sha1 (sequential) {0}".format(time.time() - t))

t = time.time()
threads = [Hasher(hashlib.sha1) for i in range(2)]
for thread in threads:
    thread.join()
print("sha1 (threaded) {0}".format(time.time() - t))

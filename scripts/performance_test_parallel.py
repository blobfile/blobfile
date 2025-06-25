import argparse
import contextlib
import hashlib
import os
import time

import blobfile as bf

CHUNK_SIZE = 2**20


@contextlib.contextmanager
def timer(name, size):
    start = time.time()
    yield
    end = time.time()
    print(f"{name}: {end - start}s {size /1e6/(end - start)}MB/s")


def verify_hash(ref_hash, path):
    with bf.BlobFile(path, "rb") as f:
        m = hashlib.md5()
        while True:
            block = f.read(CHUNK_SIZE)
            if block == b"":
                break
            m.update(block)
        assert m.hexdigest() == ref_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote-dir", required=True)
    parser.add_argument("--local-dir", required=True)
    parser.add_argument("--size", default=100_000_000, type=int)
    parser.add_argument("--loops", default=10, type=int)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    tests = [
        (
            "local_to_remote",
            bf.join(args.local_dir, f"file-{args.size}.bin"),
            bf.join(args.remote_dir, "file.bin"),
        ),
        (
            "remote_to_local",
            bf.join(args.remote_dir, f"file-{args.size}.bin"),
            bf.join(args.local_dir, "file.bin"),
        ),
    ]

    for name, src, dst in tests:
        data = os.urandom(args.size)
        with bf.BlobFile(src, "wb") as f:
            f.write(data)
        m = hashlib.md5()
        m.update(data)
        data_hash = m.hexdigest()

        with timer(f"{name}_serial", args.size * args.loops):
            for i in range(args.loops):
                dst_path = dst + str(i)
                bf.copy(src, dst_path)
                if args.verify:
                    verify_hash(data_hash, dst_path)
                bf.remove(dst_path)

        with timer(f"{name}_parallel", args.size * args.loops):
            for i in range(args.loops):
                dst_path = dst + str(i)
                bf.copy(src, dst_path, parallel=True)
                if args.verify:
                    verify_hash(data_hash, dst_path)
                bf.remove(dst_path)


if __name__ == "__main__":
    main()

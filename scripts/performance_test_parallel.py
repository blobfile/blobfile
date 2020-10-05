from blobfile.azure import build_url
import contextlib
import time
import argparse
import multiprocessing as mp

import blobfile as bf


@contextlib.contextmanager
def timer(name, size):
    start = time.time()
    yield
    end = time.time()
    print(f"{name}: {end - start} MB/s {size /1e6/(end - start)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote-dir", required=True)
    parser.add_argument("--local-dir", required=True)
    parser.add_argument("--size", default=100_000_000, type=int)
    parser.add_argument("--loops", default=10, type=int)
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
        if not bf.exists(src):
            data = (b"meow" * 249 + b"mew\n") * (args.size // 1000)
            assert len(data) == args.size
            with bf.BlobFile(src, "wb") as f:
                f.write(data)

        with timer(f"{name}_serial", args.size * args.loops):
            for i in range(args.loops):
                bf.copy(src, dst + str(i))
                bf.remove(dst + str(i))

        with timer(f"{name}_parallel", args.size * args.loops):
            for i in range(args.loops):
                bf.copy(src, dst + str(i), parallel=True)
                bf.remove(dst + str(i))


if __name__ == "__main__":
    main()

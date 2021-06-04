import contextlib
import time
import argparse
import multiprocessing as mp

import blobfile as bf
from blobfile import ops


@contextlib.contextmanager
def timer(name):
    start = time.time()
    yield
    end = time.time()
    print(f"{name}: {end - start}")


def read_worker(path: str) -> None:
    for i in range(16):
        with bf.BlobFile(path, "rb") as f:
            f.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--no-streaming-read-request", action="store_true")
    parser.add_argument("--buffer-size", default=8192, type=int)
    parser.add_argument("--size", default=1_000_000_000, type=int)
    args = parser.parse_args()

    bf.configure(use_streaming_read_request=not args.no_streaming_read_request)

    path = bf.join(args.path, "large.bin")
    data = (b"meow" * 249 + b"mew\n") * (args.size // 1000)
    with timer("write_large_file"):
        with bf.BlobFile(path, "wb") as f:
            f.write(data)

    start = time.time()
    with timer("read_large_file"):
        with bf.BlobFile(path, "rb", buffer_size=args.buffer_size) as f:
            f.read()
    end = time.time()
    print(f"MB/s {len(data) /1e6/(end - start)}")

    with timer("read_large_file_lines"):
        with bf.BlobFile(path, "r", buffer_size=args.buffer_size) as f:
            for _ in f:
                pass

    with timer("seek_speed"):
        with bf.BlobFile(path, "rb", buffer_size=args.buffer_size) as f:
            for i in range(min(10_000, args.size)):
                f.seek(i)
                f.read(1)

    count = mp.cpu_count() * 2
    start = time.time()
    with timer("multi_read"):
        procs = []
        for i in range(count):
            p = mp.Process(target=read_worker, args=(path,))
            procs.append(p)

        for p in procs:
            p.start()

        for p in procs:
            p.join()
    end = time.time()
    print(f"MB/s {count * len(data) /1e6/(end - start)}")

    filepaths = list(bf.glob(f"gs://gcp-public-data-landsat/LC08/01/001/003/**/*.TIF"))
    with timer("read_small_files"):
        for fp in filepaths[:100]:
            with bf.BlobFile(fp, "rb", buffer_size=args.buffer_size) as f:
                f.read(1)

    with timer("glob"):
        first_file_list = list(bf.glob(f"gs://gcp-public-data-landsat/LC08/01/001/**"))

    with timer("parallel_glob"):
        second_file_list = list(
            bf.glob(f"gs://gcp-public-data-landsat/LC08/01/001/**", parallel=True)
        )

    assert set(first_file_list) == set(second_file_list)


if __name__ == "__main__":
    main()

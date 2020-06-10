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
    with bf.BlobFile(path, "rb") as f:
        f.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--size", default=1_000_000, type=int)
    parser.add_argument("--no-persistent-read-file", action="store_true")
    parser.add_argument("--release-conn", action="store_true")
    args = parser.parse_args()

    if args.release_conn:
        ops.RELEASE_CONN = True

    if args.no_persistent_read_file:
        ops.PERSISTENT_READ_FILE = False

    path = bf.join(args.path, "1gb.bin")
    with timer("write_large_file"):
        with bf.BlobFile(path, "wb") as f:
            f.write((b"meow" * 249 + b"mew\n") * args.size)

    with timer("read_large_file"):
        with bf.BlobFile(path, "rb") as f:
            f.read()

    with timer("read_large_file_lines"):
        with bf.BlobFile(path, "r") as f:
            for _ in f:
                pass

    with timer("seek_speed"):
        with bf.BlobFile(path, "rb") as f:
            for i in range(10_000):
                f.seek(i)
                f.read(1)

    with timer("multi_read"):
        procs = []
        for i in range(mp.cpu_count() * 2):
            p = mp.Process(target=read_worker, args=(path,))
            procs.append(p)

        for p in procs:
            p.start()

        for p in procs:
            p.join()

    filepaths = list(bf.glob(f"gs://gcp-public-data-landsat/LC08/01/001/003/**/*.TIF"))
    with timer("read_small_files"):
        for fp in filepaths:
            with bf.BlobFile(fp, "rb") as f:
                f.read(1)

    with timer("glob"):
        first_file_list = list(bf.glob(f"gs://gcp-public-data-landsat/LC08/01/001/**"))

    with timer("parallel_glob"):
        second_file_list = list(bf.glob(f"gs://gcp-public-data-landsat/LC08/01/001/**", parallel=True))

    assert set(first_file_list) == set(second_file_list)


if __name__ == "__main__":
    main()

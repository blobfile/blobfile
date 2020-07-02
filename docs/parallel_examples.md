# Parallel Examples

### Parallel execution

```py
import blobfile as bf
import multiprocessing as mp
import tqdm

def check_exists(path):
    return path, bf.exists(path)

def main():
    filepaths = [f"gs://my-bucket/{i}.ext" for i in range(1000)]

    with mp.Pool() as pool:
        for filepath, exists in tqdm.tqdm(pool.imap_unordered(check_exists, filepaths), total=len(filepaths)):
            pass

if __name__ == "__main__":
    main()
```

### Parallel execution with [gevent](http://www.gevent.org/index.html)

This uses coroutines instead of processes/threads so may be faster in some cases.  If you're using this, you should probably also use 1 python process per core and split your work across multiple processes.

```py
from gevent import monkey
monkey.patch_all()

import tqdm
import gevent.pool
import blobfile as bf


def check_exists(path):
    return path, bf.exists(path)

def main():
    filepaths = [f"gs://my-bucket/{i}.ext" for i in range(1000)]
    pool = gevent.pool.Pool(100)
    for filepath, exists in tqdm.tqdm(pool.imap_unordered(check_exists, filepaths), total=len(filepaths)):
        pass

if __name__ == "__main__":
    main()
```

### Parallel download of a single file

```py
import blobfile as bf
import concurrent.futures
import time


def _download_chunk(path, start, size):
    with bf.BlobFile(path, "rb") as f:
        f.seek(start)
        return f.read(size)


def parallel_download(path, chunk_size=16 * 2**20):
    pieces = []
    stat = bf.stat(path)
    with concurrent.futures.ProcessPoolExecutor() as executor:
        start = 0
        futures = []
        while start < stat.size:
            future = executor.submit(_download_chunk, path, start, chunk_size)
            futures.append(future)
            start += chunk_size
        for future in futures:
            pieces.append(future.result())
    return b"".join(pieces)


def main():
    contents = parallel_download("<path to file>")


if __name__ == "__main__":
    main()
```

### Parallel copytree

```py
import blobfile as bf
import concurrent.futures
import tqdm


def _perform_op(op_tuple):
    op, src, dst = op_tuple
    if op == "copy":
        bf.copy(src, dst, overwrite=True)
    elif op == "mkdir":
        bf.makedirs(dst)
    else:
        raise Exception(f"invalid op {op}")


def copytree(src, dst):
    """
    Copy a directory tree from one location to another
    """
    if not bf.isdir(src):
        raise NotADirectoryError(f"The directory name is invalid: '{src}'")
    assert not dst.startswith(src), "dst cannot be a subdir of src"
    if not src.endswith("/"):
        src += "/"
    bf.makedirs(dst)

    with tqdm.tqdm(desc="listing") as pbar:
        ops = []
        # walk with topdown=False should be faster for nested directory trees
        for src_root, dirnames, filenames in bf.walk(src, topdown=False):
            relpath = src_root[len(src):]
            dst_root = bf.join(dst, relpath)

            if len(filenames) == 0:
                # only make empty directories, other directories will be implicitly created by copy
                ops.append(("mkdir", src_root, dst_root))
                pbar.update(1)

            # on GCS we can have a directory name that has the same name as a file
            # if that's the case, skip it since that's too confusing
            skip_filenames = set(dirnames)
            for filename in filenames:
                if filename in skip_filenames:
                    continue
                src_path = bf.join(src_root, filename)
                dst_path = bf.join(dst_root, filename)
                ops.append(("copy", src_path, dst_path))
                pbar.update(1)

    with concurrent.futures.ProcessPoolExecutor() as executor:
        list(tqdm.tqdm(executor.map(_perform_op, ops), total=len(ops), desc="copying"))


def main():
    contents = copytree("<path to source>", "<path to destination>")


if __name__ == "__main__":
    main()
```
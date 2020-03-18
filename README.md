# blobfile

This is a standalone clone of TensorFlow's [`gfile`](https://www.tensorflow.org/api_docs/python/tf/io/gfile/GFile), supporting both local paths and `gs://` (Google Cloud Storage) paths.

The main function is `BlobFile`, a replacement for `GFile`.  There are also a few additional functions, `basename`, `dirname`, and `join`, which mostly do the same thing as their `os.path` namesakes, only they also support `gs://` paths.  

Installation:

```sh
pip install blobfile
```

Usage:

```py
import blobfile as bf

with bf.BlobFile("gs://my-bucket-name/cats", "wb") as w:
    w.write(b"meow!")
```

Here are the functions:

* `BlobFile` - like `open()` but works with `gs://` paths too, data can be streamed to/from the remote file.  It accepts the following arguments:
    * `streaming`:
        * The default for `streaming` is `True` when `mode` is in `"r", "rb"` and `False` when `mode` is in `"w", "wb", "a", "ab"`.
        * `streaming=True`:
            * Reading is done without downloading the entire remote file.
            * Writing is done to the remote file directly, but only in chunks of a few MB in size.  `flush()` will not cause an early write.
            * Appending is not implemented.
        * `streaming=False`: 
            * Reading is done by downloading the remote file to a local file during the constructor.
            * Writing is done by uploading the file on `close()` or during destruction.
            * Appending is done by downloading the file during construction and uploading on `close()`.
    * `buffer_size`: number of bytes to buffer, this can potentially make reading more efficient.
    * `cache_dir`: a directory in which to cache files for reading, only valid if `streaming=False` and `mode` is in `"r", "rb"`.   You are reponsible for cleaning up the cache directory.

Some are inspired by existing `os.path` and `shutil` functions:

* `copy` - copy a file from one path to another, will do a remote copy between two remote paths on the same blob storage service
* `exists` - returns `True` if the file or directory exists
* `glob` - return files matching a glob-style pattern as a generator.  Globs can have [surprising performance characteristics](https://cloud.google.com/storage/docs/gsutil/addlhelp/WildcardNames#efficiency-consideration:-using-wildcards-over-many-objects) when used with blob storage.  Character ranges are not supported in patterns.
* `isdir` - returns `True` if the path is a directory
* `listdir` - list contents of a directory as a generator
* `makedirs` - ensure that a directory and all parent directories exist
* `remove` - remove a file
* `rmdir` - remove an empty directory
* `rmtree` - remove a directory tree
* `stat` - get the size and modification time of a file
* `walk` - walk a directory tree with a generator that yields `(dirpath, dirnames, filenames)` tuples
* `basename` - get the final component of a path
* `dirname` - get the path except for the final component
* `join` - join 2 or more paths together, inserting directory separators between each component

There are a few bonus functions:

* `get_url` - returns a url for a path along with the expiration for that url (or None)
* `md5` - get the md5 hash for a path, for GCS this is fast, but for other backends this may be slow
* `set_log_callback` - set a log callback function `log(msg: string)` to use instead of printing to stdout

## Errors

* `Error` - base class for library-specific exceptions
* `RequestFailure` - a request has failed permanently, has `message:str`, `request:Request`, and `response:urllib3.HTTPResponse` attributes.
* The following generic exceptions are raised from some functions to make the behavior similar to the original versions: `FileNotFoundError`, `FileExistsError`, `IsADirectoryError`, `NotADirectoryError`, `OSError`, `ValueError`, `io.UnsupportedOperation`

## Examples

Write and read a file:

```py
import blobfile as bf

with bf.BlobFile("gs://my-bucket/file.name", "wb") as f:
    f.write(b"meow")

print("exists:", bf.exists("gs://my-bucket/file.name"))

print("contents:", bf.BlobFile("gs://my-bucket/file.name", "rb").read())
```

Parallel execution:

```py
import blobfile as bf
import multiprocessing as mp
import tqdm

filenames = [f"{i}.ext" for i in range(1000)]

with mp.Pool() as pool:
    for filename, exists in tqdm.tqdm(zip(filenames, pool.imap(bf.exists, filenames)), total=len(filenames)):
        pass
```

Parallel download:

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
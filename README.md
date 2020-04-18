# blobfile

This is a standalone clone of TensorFlow's [`gfile`](https://www.tensorflow.org/api_docs/python/tf/io/gfile/GFile), supporting local paths, `gs://` (Google Cloud Storage) paths, and Azure Storage paths.

The main function is `BlobFile`, a replacement for `GFile`.  There are also a few additional functions, `basename`, `dirname`, and `join`, which mostly do the same thing as their `os.path` namesakes, only they also support `gs://` paths and Azure Storage paths.

## Installation

```sh
pip install blobfile
```

## Usage

```py
import blobfile as bf

with bf.BlobFile("gs://my-bucket-name/cats", "wb") as w:
    w.write(b"meow!")
```


Here are the functions:

* `BlobFile` - like `open()` but works with remote paths too, data can be streamed to/from the remote file.  It accepts the following arguments:
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

* `copy` - copy a file from one path to another, this will do a remote copy between two remote paths on the same blob storage service
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

* `get_url` - returns a url for a path (usable by an HTTP client without any authentication) along with the expiration for that url (or None)
* `md5` - get the md5 hash for a path, for GCS this is often fast, but for other backends this may be slow.  On Azure, if the md5 of a file is calculated and is missing from the file, the file will be updated with the calculated md5.
* `configure` - set global configuration options for blobfile
    * log_callback: a log callback function `log(msg: string)` to use instead of printing to stdout
    * connection_pool_max_size: the max size for each per-host connection pool

## Paths

For Google Cloud Storage and Azure Storage directories don't really exist.  These storage systems store the files in a single flat list.  The "/" separators are just part of the filenames and there is no need to call the equivalent of `os.mkdir` on one of these systems.

<!-- As a result, directories can be either "implicit" or "explicit".

* An "implicit" directory would be if the file "a/b" exists, then we would say that the directory "a" exists.  If you delete "a/b", then that directory no longer exists because no file exists with the prefix "a/".
* An "explicit" directory would be if the file "a/" exists.  All other files with the prefix "a/" could be deleted, and the directory "a" would still exist because of this dummy file. -->

To make local behavior consistent with the remote storage systems, missing local directories will be created automatically when opening a file in write mode.

### Local

These are just normal paths for the current machine, e.g. "/root/hello.txt"

### Google Cloud Storage

GCS paths have the format `gs://<bucket>/<blob>`, you cannot perform any operations on `gs://` itself.

### Azure Storage

Azure Storage URLs have the format `https://<account>.blob.core.windows.net/<container>/<blob>`.  The highest you can go up the hierarchy is `https://<account>.blob.core.windows.net/<container>/`, `blobfile` cannot perform any operations on `https://<account>.blob.core.windows.net/`.

## Errors

* `Error` - base class for library-specific exceptions
* `RequestFailure` - a request has failed permanently, has `message:str`, `request:Request`, and `response:urllib3.HTTPResponse` attributes.
* The following generic exceptions are raised from some functions to make the behavior similar to the original versions: `FileNotFoundError`, `FileExistsError`, `IsADirectoryError`, `NotADirectoryError`, `OSError`, `ValueError`, `io.UnsupportedOperation`

## Logging

 `blobfile` will keep retrying transient errors until they succeed or a permanent error is encountered (which will raise an exception).  In order to make diagnosing stalls easier, `blobfile` will log when retrying requests.

To route those log lines, use `set_log_callback` to set a callback function which will be called whenever a log line should be printed.  The default callback prints to stdout.

While `blobfile` does not use the python `logging` module, it does use `urllib3` which uses that module.  So if you configure the python `logging` module, you may need to change the settings to adjust `urllib3`'s logging.  To restrict `urllib3`'s logging to only `ERROR` level or worse, you can do `logging.getLogger("urllib3").setLevel(logging.ERROR)`.

## Examples

### Write and read a file

```py
import blobfile as bf

with bf.BlobFile("gs://my-bucket/file.name", "wb") as f:
    f.write(b"meow")

print("exists:", bf.exists("gs://my-bucket/file.name"))

print("contents:", bf.BlobFile("gs://my-bucket/file.name", "rb").read())
```

### Parallel execution

```py
import blobfile as bf
import multiprocessing as mp
import tqdm

filenames = [f"{i}.ext" for i in range(1000)]

with mp.Pool() as pool:
    for filename, exists in tqdm.tqdm(zip(filenames, pool.imap(bf.exists, filenames)), total=len(filenames)):
        pass
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

## Authentication

### Google Cloud Storage

The environment variable `GOOGLE_APPLICATION_CREDENTIALS` will be checked, falling back to "default application credentials" if they can be found.

### Azure Storage

The following methods will be tried in order:

1) Check the environment variable `AZURE_STORAGE_ACCOUNT_KEY` for an azure storage account key (these are per-storage account shared keys described in https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)
2) Check the environment variable `AZURE_APPLICATION_CREDENTIALS` which should point to JSON credentials for a service principal output by the command `az ad sp create-for-rbac --name <name>`
3) Check the environment variables `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` corresponding to a service principal described in the previous step but without the JSON file.
4) Use credentials from the `az` command line tool if they can be found.

## Changes

See [CHANGES.md](CHANGES.md)
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

* `BlobFile` - like `open()` but works with `gs://` paths too
* `LocalBlobFile` - like `BlobFile()` but operations take place on a local file.  When reading this is done by downloading the file during the constructor, for writing this means uploading the file on `close()` or during destruction.  You can pass a `cache_dir` parameter to cache files for reading.  You are reponsible for cleaning up the cache directory though.

Some are inspired by existing `os.path` and `shutil` functions:

* `copy` - copy a file from one path to another
* `exists` - returns `True` if the file or directory exists
* `glob` - return files matching a pattern, on GCS this only supports the `*` operator and can be slow if the `*` appears early in the pattern since GCS can only do prefix matches, all additional filtering must happen locally
* `isdir` - returns `True` if the path is a directory
* `listdir` - list contents of a directory
* `makedirs` - ensure that a directory and all parent directories exist
* `remove` - remove a file
* `rmdir` - remove an empty directory
* `stat` - get the size and modification time of a file
* `walk` - walk a directory tree, yielding `(dirpath, dirnames, filenames)` tuples
* `basename` - get the final component of a path
* `dirname` - get the path except for the final component
* `join` - join 2 or more paths together, inserting directory separators between each component

There are a few bonus functions:

* `cache_key` - returns a cache key that can be used for the path (this is not guaranteed to change when the content changes, but should hopefully do that)
* `get_url` - returns a url for a path along with the expiration for that url (or None)
* `md5` - get the md5 hash for a path, for GCS this is fast, but for other backends this may be slow
* `set_log_callback` - set a log callback function `log(msg: string)` to use instead of printing to stdout
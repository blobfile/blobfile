# blobfile

This is a standalone clone of TensorFlow's [`gfile`](https://www.tensorflow.org/api_docs/python/tf/io/gfile/GFile), supporting both local paths and `gs://` (Google Cloud Storage) paths.

The main function is `BlobFile`, a replacement for `GFile`.  There are also a few additional functions, `basename`, `dirname`, and `join`, which mostly do the same thing as their `os.path` namesakes, only they also support `gs://` paths.  

By default reads are copied on open() and writes on close(), set `streaming=True` to `BlobFile` to stream reads and writes instead.  GCS files are written in large chunks though, so be careful if you do a log file this way as the end could be truncated.

Here are the functions:

* `copy` - copy a file from one path to another
* `exists` - returns `True` if the file or directory exists
* `glob` - return files matching a pattern, on GCS this only supports the `*` operator and can be slow if the `*` appears early in the pattern since GCS can only do prefix matches, all additional filtering must happen locally
* `isdir` - returns `True` if the path is a directory
* `listdir` - list contents of a directory
* `makedirs` - ensure that a directory and all parent directories exist
* `remove` - remove a file
* `rename` - move a file from one path to another (source and destination must be both local or both on GCS), not atomic on GCS
* `copytree` - copy a directory tree from one path to another
* `rmtree` - remove a directory tree
* `stat` - get the size and modification time of a file
* `walk` - walk a directory tree, yielding `(dirpath, dirnames, filenames tuples)`
* `basename` - get the final component of a path
* `dirname` - get the path except for the final component
* `join` - join 2 or more paths together, inserting directory separators between each component
* `cache_key` - returns a cache key that can be used for the path (this is not guaranteed to change when the content changes, but should hopefully do that)
* `get_url` - returns a url for a path
* `md5` - get the md5 hash for a path, for GCS this is fast, but for other backends this may be slow
* `set_log_callback` - set a log callback function `log(msg: string)` to use instead of printing to stdout
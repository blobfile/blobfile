# blobfile

This is a standalone clone of TensorFlow's [`gfile`](https://www.tensorflow.org/api_docs/python/tf/io/gfile/GFile), supporting both local paths and `gs://` paths.

Writing to a remote path will not actually perform the write incrementally, so don't write to a log file this way.  By default reads and writes are streamed, set `streaming=False` to `BlobFile` to do a single copy operation per file instead.

The main function is `BlobFile`, a replacement for `GFile`.  There are also a few additional functions, `basename`, `dirname`, and `join`, which mostly do the same thing as their `os.path` namesakes, only they also support `gs://` paths.  There are also a few extra functions:

* `cache_key` - returns a cache key that can be used for the path (this is not guaranteed to change when the content changes, but should hopefully do that)
* `retry` - useful for retrying since network operations often fail
* `get_url` - returns a url for a path

A number of existing `gfile` functions are currently not implemented.
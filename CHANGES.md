# Changelog

## 0.17.2

* Allow seeking past end of file

## 0.17.1

* Fixed GCS cloud copy for large files from @hauntsaninja
* Added workaround for TextIOWrapper to buffer the same way when reading in text or binary mode
* Don't clear block blobs when starting to write to them, instead clear only the uncommitted blocks.

## 0.17.0

* Log all request failures by default rather than just errors after the first one, can now be set with the `retry_log_threshold` argument to `configure()`.  To get the previous behavior, use `bf.configure(retry_log_threshold=1)`
* Use block blobs instead of append blobs in Azure Storage, the block size can be set via the `azure_write_chunk_size` option to `configure()`.  Writing a block blob will delete any existing file before starting the writing process and writing may raise a `ConcurrentWriteFailure` in the event of multiple processes writing to the same file at the same time.  If this happens, either avoid writing concurrently to the same file, or retry after some period.
* Make service principals fall back to storage account keys and improve detection of when to fall back
* Added `set_mtime` function to set the modified time for an object
* Added `md5` to stat object, which will be the md5 hexdigest if present on a remote file.  Also add `version` which, for remote objects, represents some unique id that is changed when the file is changed.
* Improved error descriptions
* Require keyword arguments to `configure()`
* Add `scanglob` which is `glob` but returnes `DirEntry` objects instead of strings
* Add `scandir` which is `listdir` but returns `DirEntry` objects instead of strings
* `listdir` entries for local paths are no longer returned in sorted order
* Add ability to set max count of connection pools, this may be useful for Azure where each storage account has its own connection pool.
* Handle `:` with `join`

## 0.16.11

* More robust checking for azure account-does-not-exist errors
* Handle exceptions during `close()` for `_ProxyFile`
* Use `storage.googleapis.com` instead of `www.googleapis.com` for google api endpoint

## 0.16.10

* Add support for `NO_GCE_CHECK=true` environment variable used by colab notebooks
* Remove use of `copy.copy()` due to odd behavior during interpreter shutdown which could cause write-mode `BlobFile`s to not finish their final upload
* Support azure "login" method instead of just "key" method, corresponding to "AZURE_STORAGE_AUTH_MODE".  Automatically fallback to key method if login method doesn't work.
* Skip subscriptions we don't have permissions to access when getting storage keys.
* Use environment variable `AZURE_STORAGE_KEY` instead of `AZURE_STORAGE_ACCOUNT_KEY` by default
* Add support for environment variable `AZURE_STORAGE_CONNECTION_STRING`
* Don't return connections used for reading files to the connection pool to avoid a rare issue with a -1 file descriptor

## 0.16.9

* no longer allow `:` in remote paths used with `join` except for the first path provided
* add `BLOBFILE_BACKENDS` environment variable to set what backends will be available for use with `BlobFile`, it should be set to `local,google,azure` to get the default behavior of allowing all backends

## 0.16.8

* reopen streaming read files when an error is encountered in case urllib3 does not do this

## 0.16.7

* reduce readall() default chunk size to fix performance regression, thanks @jpambrun for reporting this!

## 0.16.6

* Added `configure()` to replace `set_log_callback` and add a configurable max connection pool size.
* Make `pip install` work without having to have extra tools installed
* Fix bug in response reading where requests would be retried, but reading the response body would not

## 0.16.5

* Added `topdown=False` support to `walk()`
* Added `copytree()` example

## 0.16.4

* Creating a write-mode `BlobFile` for a local path will automatically create intermediate directories to be consistent with blob storage, see https://github.com/christopher-hesse/blobfile/issues/48
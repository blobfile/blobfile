# Changelog

## Unreleased

* Support resolving objects that define `__blobpath__`
* Drop support for Python 3.7
* Various lint and test changes

## 2.0.2

* Support a `version` parameter for writing files to Azure, if the `version` doesn't match the remote version, a `VersionMismatch` error will be raised from @williamzhuk

## 2.0.1

* Fix for storing access tokens on a different filesystem than the one used for temp directories from @hponde

## 2.0.0

* Change `configure` defaults to `output_az_paths=True` and `save_access_token_to_disk=True`

## 1.3.4

* Azure timestamp parsing is now slightly faster
* Replace `xmltodict` with `lxml` as it is slightly faster
* Use lazy import for `pycryptodome` from @hauntsaninja
* Print request ids when azure auth fails

## 1.3.3

* Added new `configure` option, `multiprocessing_start_method` that defaults to `spawn`, due to issues with `fork`.  To get the original behavior back, call `bf.configure(multiprocessing_start_method="fork")`

## 1.3.2

* Fix to default value for `use_azure_storage_account_key_fallback` from @hauntsaninja

## 1.3.1

* Add support for anonymous auth for GCS
* Clarify relationship with Tensorflow's `gfile`

## 1.3.0

* `parallel` option for `bf.copy` will now use a faster copy for azure when copying between two different storage accounts
* fix a bug when reading a file from an account with read-only access and also using `cache_dir`
* better error messages when using remote copy

## 1.2.9

* `parallel` option for `rmtree`
* fix trailing semicolon with `bf.join`
* add `save_access_token_to_disk` to save local access tokens locally
* fix bug preventing parallel copy of empty file
* calculate md5 for individual uploaded blocks
* more consistent glob behavior on local paths
* don't use global random state

## 1.2.8

* Add `shard_prefix_length` to `scanglob`

## 1.2.7

* Support using access tokens from new versions of azure-cli, thanks @hauntsaninja for adding this.

## 1.2.6

* Change to use oauth v2 for azure, thanks @cjgibson for adding this.

## 1.2.5

* Fix bug in `scanglob` that marked files as directories, thanks @jacobhilton for fixing this
* Fix rare crash when writing files, thanks @unixpickle for fixing this

## 1.2.4

* `connection_pool_max_size` and `max_connection_pool_count` are no longer supported due to issues with `ProcessPoolExecutor`, instead you may specify `get_http_pool` if you need to control these settings.
* Add `file_size` argument to `BlobFile` to skip reading the size of the file on creation.

## 1.2.3

* Change `default_buffer_size` to `8 * 2**20`
* Increased the chunk size for `readall()` to `8 * 2**20`
* Fix GCS write file to respect `google_write_chunk_size`

## 1.2.2

* Added an option to disable streaming reads since azure doesn't handle it well, `use_streaming_read=False`.  These are now disabled by default.
* Added an option to set the default buffer size, `default_buffer_size`, which is important to set if you disable streaming reads.

## 1.2.1

* When uploading to a file with `streaming=True` (not the default), avoid an extra copy of the data being uploaded.  This is mostly an optimization for when you do a single large `f.write()`.

## 1.2.0

* Set `use_azure_storage_account_key_fallback` to `False` by default.  This is a backwards breaking change if you rely on storage account keys.  To go back to the previous behavior, call `bf.configure(use_azure_storage_account_key_fallback=True)`.

## 1.1.3

* Support pagination of azure management pages.

## 1.1.2

* Don't log connection aborted errors on first try.
* Use slightly different backoff jitter algorithm
* Fix `tell()` for streaming write files, this fixes a bug where zip files would not be written correctly when written to a `streaming=True` file while using the `zipfile` library.

## 1.1.1

* Add `create_context()` function to create `blobfile` instances with different configurations
* Retry azure remote copy if a copy is already in progress
* Fix bug in parallel azure upload

## 1.1.0

* Remove `BLOBFILE_BACKENDS` environment variable
* Various internal refactorings
* By default, common errors will not be logged unless a request has been retried enough times

## 1.0.7

* Attempt to query for subscriptions even less often
* Allow configuring connect and read timeouts through `bf.configure`
* Add configure option `output_az_paths`, set this to `True` to output `az://` paths instead of the `https://` ones
* Add configure option `use_azure_storage_account_key_fallback`, set this to `False` to disable falling back to storage account keys.  This is recommended because the storage key fallback confuses users and can result in 429s from the Azure management endpoints.
* Remove generated `.pyi` files.  These were for use by `pyright`, but confused PyCharm and are no longer necessary for `pyright`.
* Rename non-public modules to make it clear to `pyright` which symbols are exported.

## 1.0.6

* Fix for azure credentials when using service principals through azure cli, thanks to @hauntsaninja for the PR
* Fix for `bf.listdir` on `az://` paths in the presence of explicit directories, thanks to @WuTheFWasThat for the PR

## 1.0.5

* Add support for `az://` urls, thanks to @joschu for the PR.  All azure urls output by `blobfile` are still the `https://` format.

## 1.0.4

* Fix to `bf.isdir()` from @hauntsaninja, which didn't work on some unusual azure directories.
* Fewer calls to azure API to reduce chance of hitting rate limits, thanks to @hauntsaninja for the PR
* Tokens were being expired at the wrong time, thanks to @hauntsaninja for the PR

## 1.0.3

* Sleep when checking copy status, thanks to @hauntsaninja for the PR

## 1.0.2

* New version to work around pypi upload failure

## 1.0.1

* Better error message for bad refresh token, thanks @hauntsaninja for reporting this
* Include more error information when a request fails
* Fix `bf.copy(..., parallel=True)` logic, versions `1.0.0` and `0.17.3` could upload the wrong data when requests are retried internally by `bf.copy`.  Also azure paths were not properly escaped.

## 1.0.0

* Remove deprecated functions `LocalBlobFile` (use `BlobFile` with `streaming=False`) and `set_log_callback` (use `configure` with `log_callback=<fn>`)

## 0.17.3

* Change default write block size to 8 MB
* Add `parallel` option to `bf.copy` to do some operations in parallel as well as `parallel_executor` argument to set the executor to be used.
* Fix `bf.copy` between multiple azure storage accounts, thanks @hauntsaninja for reporting this

## 0.17.2

* Allow seeking past end of file
* Allow anonymous access for azure containers.  Try anonymous access if other methods fail and allow blobfile to work if user has no valid azure credentials.

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

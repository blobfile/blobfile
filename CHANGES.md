# Changelog

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
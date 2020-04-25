# Changelog

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
# Testing

This will auto-format the code, check the types, and then run the tests:

```sh
python run.py
```

Run a single test:

```sh
python run.py -v -s -k test_windowed_file
```

Modify `run.py` if you only want to do some of these things.  The tests are rather slow (even though large file tests are disabled) and require accounts with every cloud provider.
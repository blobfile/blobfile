import subprocess as sp
import sys

sp.run(["pip", "install", "-e", "."], check=True)
sp.run(
    ["pytest", "blobfile", "--typeguard-packages=blobfile", "-s", "-k", "test_glob"] + sys.argv[1:], check=True
)

import subprocess as sp
import sys

sp.run(["pip", "install", "-e", "."], check=True)
sp.run(["pytest", "blobfile", "-s", "-k", "test_remove"] + sys.argv[1:], check=True)

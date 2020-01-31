import subprocess as sp
import sys

sp.run(["pip", "install", "-e", "."], check=True)
sp.run(
    ["pytest", "blobfile"] + sys.argv[1:], check=True
)
# "--typeguard-packages=blobfile" does not seem to work with mp.Queue[T]

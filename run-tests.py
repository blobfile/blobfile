import subprocess as sp
import sys

sp.run(["pip", "install", "-e", "."], check=True)
sp.run(["pytest", "blobfile"] + sys.argv[1:], check=True)
# typeguard seems to be broken by mp.Queue template
# prefixes: mp.Queue[Tuple[str, str, bool]], items: mp.Queue[Optional[str]]
# E   TypeError: 'method' object is not subscriptable
# "--typeguard-packages=blobfile"

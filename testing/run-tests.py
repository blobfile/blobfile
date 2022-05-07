import subprocess as sp
import sys
import os

sp.run(["pip", "install", "-e", "."], check=True)
sp.run(["pytest", "blobfile"] + sys.argv[1:], check=True)
os.environ["BLOBFILE_FORCE_GOOGLE_ANONYMOUS_AUTH"] = "1"
sp.run(["pytest", "blobfile", "-k", "test_gcs_public"] + sys.argv[1:], check=True)

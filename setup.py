import os
from setuptools import setup, find_packages

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

README = open(os.path.join(SCRIPT_DIR, "README.md")).read()

setup_dict = dict(
    name="blobfile",
    version="0.2.3",
    description="Read GCS and local paths with the same interface, clone of tensorflow.io.gfile",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/cshesse/blobfile",
    author="Christopher Hesse",
    license="Public Domain",
    packages=find_packages(),
    install_requires=["google-cloud-storage~=1.16"],
    extras_require={"dev": ["pytest", "tensorflow", "imageio", "imageio-ffmpeg"]},
)

if os.environ.get("USE_SCM_VERSION", "1") == "1":
    setup_dict["use_scm_version"] = {
        "root": "..",
        "relative_to": __file__,
        "local_scheme": "node-and-timestamp",
    }
    setup_dict["setup_requires"] = ["setuptools_scm"]

setup(**setup_dict)

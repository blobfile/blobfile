import os
import shutil
from setuptools import setup, find_packages
import setuptools.command.build_py
import subprocess as sp


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

README = open(os.path.join(SCRIPT_DIR, "README.md")).read()


class BuildPyCommand(setuptools.command.build_py.build_py):
    def run(self):
        sp.run(
            ["pyright", "--project", "pyrightconfig.json", "--createstub", "blobfile"],
            check=True,
            shell=True,
        )
        sp.run(
            [
                "python",
                "scripts/filter-stubs.py",
                "--stubspath",
                "typings/blobfile",
                "--outputpath",
                "blobfile",
            ],
            check=True,
        )
        shutil.rmtree("typings/blobfile")
        setuptools.command.build_py.build_py.run(self)


setup_dict = dict(
    name="blobfile",
    version="1.0.2",
    description="Read GCS and local paths with the same interface, clone of tensorflow.io.gfile",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/christopher-hesse/blobfile",
    author="Christopher Hesse",
    license="Public Domain",
    packages=find_packages(),
    install_requires=[
        "pycryptodomex~=3.8",
        "urllib3~=1.25",
        "xmltodict~=0.12.0",
        "filelock~=3.0",
    ],
    extras_require={
        "dev": [
            "pytest",
            "tensorflow",
            "imageio",
            "imageio-ffmpeg",
            "azure-cli",
            "google-cloud-storage",
        ]
    },
    python_requires=">=3.7.0",
    # indicate that we have type information
    package_data={"blobfile": ["*.pyi", "py.typed"]},
    # mypy cannot find type information in zip files
    zip_safe=False,
)

if os.environ.get("PACKAGE_FOR_RELEASE", "0") == "1":
    # don't require that users have all the build requirements when doing "pip install"
    # since these are only used for creating the stub files
    setup_dict["cmdclass"] = {"build_py": BuildPyCommand}

if os.environ.get("USE_SCM_VERSION", "0") == "1":
    setup_dict["use_scm_version"] = {
        "root": "..",
        "relative_to": __file__,
        "local_scheme": "node-and-timestamp",
    }
    setup_dict["setup_requires"] = ["setuptools_scm"]

setup(**setup_dict)

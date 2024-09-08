import runpy
from setuptools import find_packages, setup

PACKAGE_NAME = "ALLOSAUR"
version_meta = runpy.run_path("./{}/version.py".format(PACKAGE_NAME))
VERSION = version_meta["__version__"]

if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        author="Victor Huang <280355648@qq.com>, Michael Lodder <redmike7@gmail.com>",
        url="https://github.com/mikelodder7/oberon",
        packages=find_packages(),
        include_package_data=True,
        package_data={
            "": [
                "agora_allosaurus_rs.dll",
                "libagora_allosaurus_rs.dylib",
                "libagora_allosaurus_rs.so",
            ]
        },
        python_requires=">=3.9.0",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
        ],
    )
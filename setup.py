from setuptools import setup, find_packages

setup(
    name="cdispyutils",
    version="0.2.0",
    description="General utilities for Gen3 development",
    license="Apache",
    install_requires=[
        "six==1.11.0",
        "requests==2.13.0",
        "PyJWT==1.5.3",
        "cryptography==2.1.2",
    ],
    packages=find_packages(),
)


from setuptools import setup, find_packages

setup(
    name="cdispyutils",
    version="0.1.0",
    description="General utilities",
    license="Apache",
    install_requires=[
        "six==1.10.0",
        "requests==2.13.0",
    ],
    packages=find_packages(),
)

from setuptools import setup, find_packages

setup(
    name="cdispyutils",
    version="0.1.0",
    description="General utilities",
    license="Apache",
    install_requires=[
        "cryptography==2.1.2",
        "PyJWT==1.5.3",
        "requests==2.18.4",
        "six==1.11.0",
    ],
    packages=find_packages(),
)

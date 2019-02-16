from setuptools import setup, find_packages

setup(
    name="cdispyutils",
    version="0.2.11",
    description="General utilities for Gen3 development",
    license="Apache",
    install_requires=[
        "cryptography>=2.1.2",
        "PyJWT>=1.5.3",
        'requests>=2.5.2,<3.0.0',
        "six>=1.11.0",
        "cdiserrors>=0.1.1",
    ],
    extras_require=dict(
        uwsgi=[
            "Flask",
        ],
        profiling=[
            "Werkzeug>=0.9.6,<1.0.0",
            "matplotlib>=2.2.3,<3.0.0",
            "numpy>=1.15.4,<2.0.0",
        ],
    ),
    packages=find_packages(),
)

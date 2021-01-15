from subprocess import check_output

from setuptools import setup, find_packages


def get_version():
    # https://github.com/uc-cdis/dictionaryutils/pull/37#discussion_r257898408
    try:
        tag = check_output(
            ["git", "describe", "--tags", "--abbrev=0", "--match=[0-9]*"]
        )
        return tag.decode("utf-8").strip("\n")
    except Exception:
        raise RuntimeError(
            "The version number cannot be extracted from git tag in this source "
            "distribution; please either download the source from PyPI, or check out "
            "from GitHub and make sure that the git CLI is available."
        )


setup(
    name="cdispyutils",
    version=get_version(),
    description="General utilities for Gen3 development",
    license="Apache",
    install_requires=[
        "cryptography==3.2",
        "PyJWT~=1.5",
        "requests~=2.5",
        "cdiserrors~=1.0.0",
        "Flask",
    ],
    extras_require=dict(profiling=["Werkzeug~=0.9", "matplotlib~=2.2", "numpy~=1.15"]),
    packages=find_packages(),
)

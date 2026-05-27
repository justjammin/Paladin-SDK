from setuptools import setup, find_packages

setup(
    name="paladin",
    version="0.1.0",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.11",
    install_requires=[
        "paladin-sentinel",
        "paladin-bulwark",
        "paladin-vault",
        "paladin-chronicle",
    ],
)

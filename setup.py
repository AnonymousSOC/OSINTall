#!/usr/bin/env python3
"""
Setup configuration for osintall - Comprehensive OSINT Framework for Kali Linux
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="osintall",
    version="1.0.0",
    author="OSINTALL Team",
    description="All-in-One OSINT Reconnaissance Framework for Kali Linux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/osintall",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "osintall=osintall:main",
        ],
    },
)

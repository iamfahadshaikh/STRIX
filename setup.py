from pathlib import Path

from setuptools import setup, find_packages


README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")

setup(
    name="strix-security",
    version="0.1.0",
    description="Precision-driven VAPT orchestration engine with intelligent gating and proof-based reporting",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Fahad Shaikh",
    url="https://github.com/iamfahadshaikh/VAPT-Automated-Engine",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests", "docs", "example_config"]),
    install_requires=[
        "httpx>=0.27.0",
        "requests>=2.32.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.2.0",
        "python-dateutil>=2.9.0",
        "pyyaml>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "strix=strix:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="security vapt pentesting orchestration vulnerability assessment",
    project_urls={
        "Bug Reports": "https://github.com/iamfahadshaikh/VAPT-Automated-Engine/issues",
        "Documentation": "https://github.com/iamfahadshaikh/VAPT-Automated-Engine/tree/main/docs",
        "Source": "https://github.com/iamfahadshaikh/VAPT-Automated-Engine",
    },
)

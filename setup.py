from setuptools import setup, find_packages

setup(
    name="escrowai-encrypt",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        # Add your package dependencies here
        "azure-storage-blob",
        "cryptography",
        "pyyaml",
    ],
    include_package_data=True,
    description="This package allows EscrowAI users to programmatically encrypt their artifacts and add encryption to their workflows.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/BeeKeeperAI/escrowai-encrypt",
    author="BeeKeeperAI",
    author_email="engineering@beekeeperai.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "encrypt = escrowai_encrypt.main:main",
        ],
    },
)

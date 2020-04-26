import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="checksec.py",
    version="0.0.1",
    author="Mathieu Tarral",
    author_email="mathieu.tarral@protonmail.com",
    description="Checksec tool implemented in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wenzel/checksec.py",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'checksec.py = checksec.__main__:main'
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.4',
)

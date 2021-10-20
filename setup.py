import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="checksec.py",
    version="0.6.2",
    author="Mathieu Tarral",
    author_email="mathieu.tarral@protonmail.com",
    description="Checksec tool implemented in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Wenzel/checksec.py",
    packages=setuptools.find_packages(),
    install_requires=[
        "lief==0.11.0",
        "docopt==0.6.2",
        "rich==7.1.0",
        "pylddwrap==1.0.1",
    ],
    entry_points={
        "console_scripts": ["checksec = checksec.__main__:entrypoint"],
    },
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Development Status :: 4 - Beta",
        "Typing :: Typed",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    python_requires=">=3.7",
)

<h1 align="center">
  <br>checksec.py</br>
</h1>

<h3 align="center">
Checksec tool in Python, Rich output, based on LIEF
</h3>

<p align="center">
  <a href="https://github.com/Wenzel/checksec.py/actions?query=workflow%3ACI">
    <img src="https://github.com/Wenzel/checksec.py/workflows/CI/badge.svg" alt="CI badge"/>
  </a>
  <a href="https://pypi.org/project/checksec.py/">
    <img src="https://img.shields.io/pypi/v/checksec.py?color=green" alt="PyPI package badge"/>
  </a>
  <a href="https://pypi.org/project/checksec.py/">
    <img src="https://img.shields.io/pypi/pyversions/checksec.py" alt="Python version badge"/>
  </a>
</p>

## Overview

A simple tool to verify the security properties of your binaries.

Based on:
- [Rich](https://github.com/willmcgugan/rich): Beautiful terminal output formatting
- [LIEF](https://github.com/lief-project/LIEF): Cross-platform library to parse, modify and abstract ELF, PE and Mach-O formats

Supported formats:

- [x] `ELF`
- [x] `PE`
- [ ] `Mach-O`

## Requirements

- `Python 3.6`
- `virtualenv`

## Setup

~~~
virtualenv -p python3 venv
source venv/bin/activate
(venv) pip install .
~~~

## Usage

~~~
(venv) checkec <file_or_directory>...
~~~

### Example: `/usr/local/bin`

![analyzing_local_bin](https://user-images.githubusercontent.com/964610/94361570-87a8cf80-00b5-11eb-8edd-5d579f15baaf.png)

Check `--help` for more options

## References

- [@apogiatzis](https://github.com/apogiatzis) [Gist checksec.py](https://gist.github.com/apogiatzis/fb617cd118a9882749b5cb167dae0c5d)
- [checksec.sh](https://github.com/slimm609/checksec.sh)
- [winchecksec](https://github.com/trailofbits/winchecksec)

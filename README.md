<h1 align="center">
  <br>checksec.py</br>
</h1>

<h3 align="center">
Checksec tool in Python, based on LIEF
</h3>

<p align="center">
  <a href="https://github.com/Wenzel/checksec.py/actions?query=workflow%3ACI">
    <img src="https://github.com/Wenzel/checksec.py/workflows/CI/badge.svg" alt="CI badge"/>
  </a>
  <a href="https://pypi.org/project/checksec.py/">
    <img src="https://img.shields.io/pypi/v/checksec.py?color=green" alt="PyPI package badge"/>
  </a>
  <a href="">
    <img src="https://img.shields.io/pypi/pyversions/checksec.py" alt="Python version badge"/>
  </a>
</p>

## Overview

A simple tool to verify the security properties of your binaries.

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

## References

- [@apogiatzis](https://github.com/apogiatzis) [Gist checksec.py](https://gist.github.com/apogiatzis/fb617cd118a9882749b5cb167dae0c5d)

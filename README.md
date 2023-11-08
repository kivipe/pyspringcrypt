# Python replacement for Spring Crypt

![Tests](https://github.com/kivipe/pyspringcrypt/actions/workflows/tests.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/kivipe/pyspringcrypt/badge.svg?branch=coveralls)](https://coveralls.io/github/kivipe/pyspringcrypt?branch=coveralls)

This library aims to be a Pythonic replacement for `spring encrypt` and `spring decrypt` commands.

## Usage

```shell
$ python -m pyspringcrypt encrypt --key my_key plaintext
e5241d57033627657c5ebf77b819184cdb53f45409aefbc148aa7f624100fa2f

$ python -m pyspringcrypt decrypt --key my_key e5241d57033627657c5ebf77b819184cdb53f45409aefbc148aa7f624100fa2f
plaintext
```

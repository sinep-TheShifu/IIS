#!/usr/bin/python3
from sys import stderr


def eprint(*args, **kwargs):
    """Prints error messages to stderr. """
    print(*args, file=stderr, **kwargs)

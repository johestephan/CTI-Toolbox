"""Backward compatibility shim for slowcook."""

from cti_toolbox.providers.slowcook import *
from cti_toolbox.providers.slowcook import main

if __name__ == "__main__":
    main()
"""Backward compatibility shim for indifetch."""

from cti_toolbox.extract.indicators import *
from cti_toolbox.extract.indicators import main

if __name__ == "__main__":
    main()

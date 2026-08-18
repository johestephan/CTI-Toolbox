"""Backward compatibility shim for xfexchange."""

from cti_toolbox.providers.xforce import *
from cti_toolbox.providers.xforce import main

if __name__ == "__main__":
    main()

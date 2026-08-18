"""Backward compatibility shim for MispXfeWrapper."""

from cti_toolbox.providers.misp import *
from cti_toolbox.providers.misp import main

if __name__ == "__main__":
    main()

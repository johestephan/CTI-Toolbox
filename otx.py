"""Backward compatibility shim for otx."""

from cti_toolbox.providers.otx import *
from cti_toolbox.providers.otx import main

if __name__ == "__main__":
    main()

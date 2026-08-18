"""Backward compatibility shim for google_safebrowsing."""

from cti_toolbox.providers.safebrowsing import *
from cti_toolbox.providers.safebrowsing import main

if __name__ == "__main__":
    main()
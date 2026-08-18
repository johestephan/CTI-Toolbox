"""Backward compatibility shim for myrsstool."""

from cti_toolbox.extract.rss import *
from cti_toolbox.extract.rss import main

if __name__ == "__main__":
    main()

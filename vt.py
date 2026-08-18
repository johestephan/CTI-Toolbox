"""Backward compatibility shim for vt."""

from cti_toolbox.providers.virustotal import *
from cti_toolbox.providers.virustotal import main

if __name__ == "__main__":
    main()

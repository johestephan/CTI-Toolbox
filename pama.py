"""Backward compatibility shim for pama."""

from cti_toolbox.providers.packetmail import *
from cti_toolbox.providers.packetmail import main

if __name__ == "__main__":
    main()

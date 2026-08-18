"""Backward compatibility shim for redactit."""

from cti_toolbox.defang.redact import *
from cti_toolbox.defang.redact import main

if __name__ == "__main__":
    main()

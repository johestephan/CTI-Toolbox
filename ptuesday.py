"""Backward compatibility shim for ptuesday."""

from cti_toolbox.providers.sans_isc import *
from cti_toolbox.providers.sans_isc import main

if __name__ == "__main__":
    main()

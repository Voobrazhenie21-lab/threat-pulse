"""Execution wrapper for python -m threat_pulse."""

import sys
from threat_pulse.cli import main

if __name__ == "__main__":
    sys.exit(main())

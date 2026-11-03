"""Allow ``python -m mirage`` as an entry point."""

import sys

from mirage.cli import main

if __name__ == "__main__":
    sys.exit(main())

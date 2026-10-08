"""Allow ``python -m patch_report``."""

import sys

from .cli import main

sys.exit(main())

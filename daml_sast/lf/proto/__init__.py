from __future__ import annotations

import os
import sys

# Ensure generated protobuf modules with absolute package paths resolve.
_PROTO_ROOT = os.path.dirname(__file__)
if _PROTO_ROOT not in sys.path:
    sys.path.append(_PROTO_ROOT)

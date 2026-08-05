"""Where the runtime finds its schemas and templates, installed or in a checkout.

The six schemas and the three templates are the only files the runtime reads from its own
distribution. Everything else a run touches belongs to the user's workspace.

There is exactly one copy of each in the repository, at its authoritative path — `spec/` and
`templates/`. Packaging maps those directories into the installed package rather than duplicating
them, so the bytes that ship are the bytes the specifications name.
"""

from importlib import resources
from pathlib import Path

SCHEMA_PACKAGE = "vfy._schemas"
TEMPLATE_PACKAGE = "vfy._templates"

_CHECKOUT = Path(__file__).resolve().parent.parent


def schema_dir():
    """The directory holding `*.schema.json`."""
    return _resolve(SCHEMA_PACKAGE, "spec")


def template_dir():
    """The directory holding the three launch rulebooks."""
    return _resolve(TEMPLATE_PACKAGE, "templates")


def _resolve(package, checkout_name):
    """Prefer the installed distribution; fall back to the checkout it was built from.

    An installed package must never depend on a source tree, so the resource lookup comes first
    and the fallback exists only for running the tests straight out of a clone. A release test
    proves an installed wheel takes the first path and never the second.
    """
    try:
        return Path(str(resources.files(package)))
    except (ModuleNotFoundError, TypeError):
        return _CHECKOUT / checkout_name

# snyk_tags/__init__.py

__app_name__ = "snyk_tags"
__version__ = "1.0.2"

from logging import ERROR
from sre_constants import SUCCESS


(
    SUCCESS,
    ERROR,
) = range(2)

ERRORS = {ERROR: "ID Error"}

# snyk_tags/__init__.py

__app_name__ = "snyk_tags"
try:
    from importlib.metadata import version

    __version__ = version(__app_name__)

except ImportError:
    __version__ = "development"


from logging import ERROR
from sre_constants import SUCCESS


(
    SUCCESS,
    ERROR,
) = range(2)

ERRORS = {ERROR: "ID Error"}

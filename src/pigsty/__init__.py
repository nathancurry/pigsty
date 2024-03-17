from importlib.metadata import PackageNotFoundError, version

DISTRIBUTION_NAME = "pigsty"
try:
    __version__ = version(DISTRIBUTION_NAME)
except PackageNotFoundError:
    __version__ = None
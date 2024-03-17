import argparse
from .. import __version__

DESCRIPTION = "Access data from DISA STIG checklist files and other related XML data formats."
VERSION = __version__

def prepare_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pigsty",
        description=DESCRIPTION,
        add_help=True,
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s " + VERSION,
        help="Show program's version number and exit."
        )
    return parser

class Cli():
    def __init__(self, args=None):
        self.arguments = prepare_parser().parse_args(args)

    def run(self):
        pass
from pathlib import Path


class ErrorParsingFailed(Exception):
    def __init__(self, filepath: Path):
        self.path = filepath

    def __str__(self):
        return f"LIEF failed to parse valid ELF {self.path}"

from pathlib import Path


class ErrorNotAnElf(Exception):
    def __init__(self, filepath: Path):
        self.path = filepath

    def __str__(self):
        return f"File {self.path} is not an ELF"


class ErrorParsingFailed(Exception):
    def __init__(self, filepath: Path):
        self.path = filepath

    def __str__(self):
        return f"LIEF failed to parse valid ELF {self.path}"

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table


class AbstractChecksecOutput(ABC):
    def __init__(self, total: int):
        """

        :param total: Total number of checksec elements to be processed
        """
        self.total = total

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return

    @abstractmethod
    def add_checksec_result(self, filepath: Path, checksec_res: Dict[str, str]):
        """Add a checksec file result to the output"""
        raise NotImplementedError

    @abstractmethod
    def checksec_result_end(self):
        """This method is trigger for every file processed, even if the processing failed."""
        raise NotImplementedError

    @abstractmethod
    def print(self):
        """Print output on stdout"""
        raise NotImplementedError


class RichOutput(AbstractChecksecOutput):
    def __init__(self, total: int):
        """Init Rich Console and Table"""
        super().__init__(total)
        # init table
        self.table = Table(title="Checksec Results", expand=True)
        self.table.add_column("File", justify="left", header_style="")
        self.table.add_column("Relro", justify="center")
        self.table.add_column("Canary", justify="center")
        self.table.add_column("NX", justify="center")
        self.table.add_column("PIE", justify="center")
        self.table.add_column("RPATH", justify="center")
        self.table.add_column("RUNPATH", justify="center")
        self.table.add_column("Symbols", justify="center")
        self.table.add_column("Fortified", justify="center")
        self.table.add_column("Fortifiable", justify="center")
        self.table.add_column("Fortify Score", justify="center")

        # build progress bar
        self.progress_bar = Progress(
            TextColumn("[bold blue]Processing...", justify="left"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
        )
        # init console
        self.console = Console()

        # init progress bar
        self.bar = self.progress_bar.__enter__()
        self.task_id = self.bar.add_task("Checking", total=self.total)

    def add_checksec_result(self, filepath: Path, checksec_res: Dict[str, str]):
        self.table.add_row(
            str(filepath),
            checksec_res["relro"],
            checksec_res["canary"],
            checksec_res["nx"],
            checksec_res["pie"],
            checksec_res["rpath"],
            checksec_res["runpath"],
            checksec_res["symbols"],
            checksec_res["fortified"],
            checksec_res["fortifiable"],
            checksec_res["fortified_score"],
        )

    def checksec_result_end(self):
        """Update progress bar"""
        self.bar.update(self.task_id, advance=1)

    def print(self):
        self.progress_bar.__exit__(None, None, None)
        self.console.print(self.table)

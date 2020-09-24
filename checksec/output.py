import json
from abc import ABC, abstractmethod
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from checksec.elf import ELFChecksecData, PIEType, RelroType


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
    def add_checksec_result(self, filepath: Path, checksec: ELFChecksecData):
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
        self.table.add_column("FORTIFY", justify="center")
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

    def add_checksec_result(self, filepath: Path, checksec: ELFChecksecData):
        # display results
        relro = checksec.relro
        if relro == RelroType.No:
            relro_res = f"[red]{relro.name}"
        elif relro == RelroType.Partial:
            relro_res = f"[yellow]{relro.name}"
        else:
            relro_res = f"[green]{relro.name}"

        if not checksec.canary:
            canary_res = "[red]No"
        else:
            canary_res = "[green]Yes"

        if not checksec.nx:
            nx_res = "[red]No"
        else:
            nx_res = "[green]Yes"

        pie = checksec.pie
        if pie == PIEType.No:
            pie_res = f"[red]{pie.name}"
        elif pie == PIEType.DSO:
            pie_res = f"[yellow]{pie.name}"
        else:
            pie_res = "[green]Yes"

        if checksec.rpath:
            rpath_res = "[red]Yes"
        else:
            rpath_res = "[green]No"

        if checksec.runpath:
            runpath_res = "[red]Yes"
        else:
            runpath_res = "[green]No"

        if checksec.symbols:
            symbols_res = "[red]Yes"
        else:
            symbols_res = "[green]No"

        fortified_count = checksec.fortified
        if checksec.fortify_source:
            fortify_source_res = "[green]Yes"
        else:
            fortify_source_res = "[red]No"

        if fortified_count == 0:
            fortified_res = "[red]No"
        else:
            fortified_res = f"[green]{fortified_count}"

        fortifiable_count = checksec.fortifiable
        if fortified_count == 0:
            fortifiable_res = "[red]No"
        else:
            fortifiable_res = f"[green]{fortifiable_count}"

        if checksec.fortify_score == 0:
            fortified_score_res = f"[red]{checksec.fortify_score}"
        elif checksec.fortify_score == 100:
            fortified_score_res = f"[green]{checksec.fortify_score}"
        else:
            fortified_score_res = f"[yellow]{checksec.fortify_score}"

        self.table.add_row(
            str(filepath),
            relro_res,
            canary_res,
            nx_res,
            pie_res,
            rpath_res,
            runpath_res,
            symbols_res,
            fortify_source_res,
            fortified_res,
            fortifiable_res,
            fortified_score_res,
        )

    def checksec_result_end(self):
        """Update progress bar"""
        self.bar.update(self.task_id, advance=1)

    def print(self):
        self.progress_bar.__exit__(None, None, None)
        self.console.print(self.table)


class JSONOutput(AbstractChecksecOutput):
    def __init__(self, total: int):
        super().__init__(total)
        self.data = {}

    def add_checksec_result(self, filepath: Path, checksec: ELFChecksecData):
        self.data[str(filepath)] = {
            "relro": checksec.relro.name,
            "canary": checksec.canary,
            "nx": checksec.nx,
            "pie": checksec.pie.name,
            "rpath": checksec.rpath,
            "runpath": checksec.runpath,
            "symbols": checksec.symbols,
            "fortify_source": checksec.fortify_source,
            "fortified": checksec.fortified,
            "fortify-able": checksec.fortifiable,
            "fortify_score": checksec.fortify_score,
        }

    def checksec_result_end(self):
        pass

    def print(self):
        json_output = json.dumps(self.data, indent=4)
        print(json_output)

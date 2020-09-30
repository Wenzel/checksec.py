import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union

from lief.PE import MACHINE_TYPES
from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from checksec.elf import ELFChecksecData, PIEType, RelroType
from checksec.pe import PEChecksecData


class AbstractChecksecOutput(ABC):
    def __init__(self):
        self.total = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return

    def enumerating_tasks_start(self):
        """The tasks enumeration will be started"""
        pass

    def enumerating_tasks_stop(self, total: int):
        """The tasks enumeration has stopped"""
        self.total = total

    def processing_tasks_start(self):
        """Task processing has started"""
        pass

    @abstractmethod
    def add_checksec_result(self, filepath: Path, checksec: Union[ELFChecksecData, PEChecksecData]):
        """Add a checksec file result to the output"""
        raise NotImplementedError

    def checksec_result_end(self):
        """This method is trigger for every file processed, even if the processing failed."""
        pass

    @abstractmethod
    def print(self):
        """Print output on stdout"""
        raise NotImplementedError


class RichOutput(AbstractChecksecOutput):
    def __init__(self):
        """Init Rich Console and Table"""
        super().__init__()
        # init ELF table
        self.table_elf = Table(title="Checksec Results: ELF", expand=True)
        self.table_elf.add_column("File", justify="left", header_style="")
        self.table_elf.add_column("NX", justify="center")
        self.table_elf.add_column("PIE", justify="center")
        self.table_elf.add_column("Canary", justify="center")
        self.table_elf.add_column("Relro", justify="center")
        self.table_elf.add_column("RPATH", justify="center")
        self.table_elf.add_column("RUNPATH", justify="center")
        self.table_elf.add_column("Symbols", justify="center")
        self.table_elf.add_column("FORTIFY", justify="center")
        self.table_elf.add_column("Fortified", justify="center")
        self.table_elf.add_column("Fortifiable", justify="center")
        self.table_elf.add_column("Fortify Score", justify="center")

        # init PE table
        self.table_pe = Table(title="Checksec Results: PE", expand=True)
        self.table_pe.add_column("File", justify="left", header_style="")
        self.table_pe.add_column("NX", justify="center")
        self.table_pe.add_column("Canary", justify="center")
        self.table_pe.add_column("ASLR", justify="center")
        self.table_pe.add_column("Dynamic Base", justify="center")
        self.table_pe.add_column("High Entropy VA", justify="center")
        self.table_pe.add_column("SEH", justify="center")
        self.table_pe.add_column("SafeSEH", justify="center")
        self.table_pe.add_column("Force Integrity", justify="center")
        self.table_pe.add_column("Control Flow Guard", justify="center")
        self.table_pe.add_column("Isolation", justify="center")

        # init console
        self.console = Console()

        # build progress bar
        self.process_bar = Progress(
            TextColumn("[bold blue]Processing...", justify="left"),
            BarColumn(bar_width=None),
            "{task.completed}/{task.total}",
            "•",
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=self.console,
        )
        self.display_res_bar = Progress(
            BarColumn(bar_width=None),
            TextColumn("[bold blue]{task.description}", justify="center"),
            BarColumn(bar_width=None),
            console=self.console,
            transient=True,
        )
        self.enumerate_bar = Progress(
            TextColumn("[bold blue]Enumerating...", justify="center"),
            BarColumn(bar_width=None),
            console=self.console,
            transient=True,
        )

        self.process_task_id = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        # cleanup the Rich progress bars
        if self.enumerate_bar is not None:
            self.enumerate_bar.stop()
        if self.process_bar is not None:
            self.process_bar.stop()
        if self.display_res_bar is not None:
            self.display_res_bar.stop()

    def enumerating_tasks_start(self):
        # start progress bar
        self.enumerate_bar.start()
        self.enumerate_bar.add_task("Enumerating", start=False)

    def enumerating_tasks_stop(self, total: int):
        super().enumerating_tasks_stop(total)
        self.enumerate_bar.stop()
        self.enumerate_bar = None

    def processing_tasks_start(self):
        # init progress bar
        self.process_bar.start()
        self.process_task_id = self.process_bar.add_task("Checking", total=self.total)

    def add_checksec_result(self, filepath: Path, checksec: Union[ELFChecksecData, PEChecksecData]):
        if isinstance(checksec, ELFChecksecData):
            # display results
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

            if not checksec.canary:
                canary_res = "[red]No"
            else:
                canary_res = "[green]Yes"

            relro = checksec.relro
            if relro == RelroType.No:
                relro_res = f"[red]{relro.name}"
            elif relro == RelroType.Partial:
                relro_res = f"[yellow]{relro.name}"
            else:
                relro_res = f"[green]{relro.name}"

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

            self.table_elf.add_row(
                str(filepath),
                nx_res,
                pie_res,
                canary_res,
                relro_res,
                rpath_res,
                runpath_res,
                symbols_res,
                fortify_source_res,
                fortified_res,
                fortifiable_res,
                fortified_score_res,
            )
        elif isinstance(checksec, PEChecksecData):
            if not checksec.nx:
                nx_res = "[red]No"
            else:
                nx_res = "[green]Yes"

            if not checksec.canary:
                canary_res = "[red]No"
            else:
                canary_res = "[green]Yes"

            if not checksec.aslr:
                aslr_res = "[red]No"
            else:
                aslr_res = "[green]Yes"

            if not checksec.dynamic_base:
                dynamic_base_res = "[red]No"
            else:
                dynamic_base_res = "[green]Yes"

            # this is only relevant is binary is 64 bits
            if checksec.machine == MACHINE_TYPES.AMD64:
                if not checksec.high_entropy_va:
                    entropy_va_res = "[red]No"
                else:
                    entropy_va_res = "[green]Yes"
            else:
                entropy_va_res = "/"

            if not checksec.seh:
                seh_res = "[red]No"
            else:
                seh_res = "[green]Yes"

            # only relevant if 32 bits
            if checksec.machine == MACHINE_TYPES.I386:
                if not checksec.safe_seh:
                    safe_seh_res = "[red]No"
                else:
                    safe_seh_res = "[green]Yes"
            else:
                safe_seh_res = "/"

            if not checksec.force_integrity:
                force_integrity_res = "[red]No"
            else:
                force_integrity_res = "[green]Yes"

            if not checksec.guard_cf:
                guard_cf_res = "[red]No"
            else:
                guard_cf_res = "[green]Yes"

            if not checksec.isolation:
                isolation_res = "[red]No"
            else:
                isolation_res = "[green]Yes"

            self.table_pe.add_row(
                str(filepath),
                nx_res,
                canary_res,
                aslr_res,
                dynamic_base_res,
                entropy_va_res,
                seh_res,
                safe_seh_res,
                force_integrity_res,
                guard_cf_res,
                isolation_res,
            )
        else:
            raise NotImplementedError

    def checksec_result_end(self):
        """Update progress bar"""
        self.process_bar.update(self.process_task_id, advance=1)

    def print(self):
        self.process_bar.stop()
        self.process_bar = None

        if self.table_elf.row_count > 0:
            with self.display_res_bar:
                task_id = self.display_res_bar.add_task("Displaying Results: ELF ...", start=False)
                self.console.print(self.table_elf)
                self.display_res_bar.remove_task(task_id)
        if self.table_pe.row_count > 0:
            with self.display_res_bar:
                task_id = self.display_res_bar.add_task("Displaying Results: PE ...", start=False)
                self.console.print(self.table_pe)
                self.display_res_bar.remove_task(task_id)

        self.display_res_bar.stop()
        self.display_res_bar = None


class JSONOutput(AbstractChecksecOutput):
    def __init__(self):
        super().__init__()
        self.data = {}

    def add_checksec_result(self, filepath: Path, checksec: Union[ELFChecksecData, PEChecksecData]):
        if isinstance(checksec, ELFChecksecData):
            self.data[str(filepath.resolve())] = {
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
        elif isinstance(checksec, PEChecksecData):
            self.data[str(filepath.resolve())] = {
                "nx": checksec.nx,
                "canary": checksec.canary,
                "aslr": checksec.aslr,
                "dynamic_base": checksec.dynamic_base,
                "high_entropy_va": checksec.high_entropy_va,
                "isolation": checksec.isolation,
                "seh": checksec.seh,
                "safe_seh": checksec.safe_seh,
                "guard_cf": checksec.guard_cf,
            }
        else:
            raise NotImplementedError

    def checksec_result_end(self):
        pass

    def print(self):
        json_output = json.dumps(self.data, indent=4)
        print(json_output)

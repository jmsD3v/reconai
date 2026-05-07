"""
Base agent interface. All agents inherit from BaseAgent.

Each agent:
  1. Receives a Target and a ReconResult to append findings to
  2. Runs its logic (async)
  3. Appends Finding objects to result — never returns data directly
  4. Handles its own exceptions without crashing the orchestrator
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from rich.console import Console

from reconai.core.target import Target
from reconai.types.findings import Finding, FindingType, ReconResult, Severity

console = Console()


class BaseAgent(ABC):
    name: str = "base"
    description: str = ""

    async def execute(self, target: Target, result: ReconResult) -> float:
        """
        Wrapper around run() that measures time and catches top-level errors.
        Returns elapsed seconds.
        """
        start = time.perf_counter()
        try:
            await self.run(target, result)
        except Exception as exc:
            result.error_count += 1
            result.add(
                Finding(
                    agent=self.name,
                    type=FindingType.ERROR,
                    title=f"Agent error — {self.name}",
                    description=str(exc),
                    severity=Severity.INFO,
                    data={"exception": type(exc).__name__},
                )
            )
        elapsed = time.perf_counter() - start
        return elapsed

    @abstractmethod
    async def run(self, target: Target, result: ReconResult) -> None:
        """Agent implementation. Append findings to result."""
        ...

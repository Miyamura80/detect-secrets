"""Timing utilities and BenchmarkResult dataclass."""
import statistics
import time
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional


@dataclass
class BenchmarkResult:
    name: str
    unit: str = 'seconds'
    count: int = 0
    iterations: int = 0
    timings: List[float] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def stats(self) -> Dict[str, float]:
        if not self.timings:
            return {'mean': 0, 'median': 0, 'stddev': 0, 'min': 0, 'max': 0}
        return {
            'mean': statistics.mean(self.timings),
            'median': statistics.median(self.timings),
            'stddev': statistics.stdev(self.timings) if len(self.timings) > 1 else 0.0,
            'min': min(self.timings),
            'max': max(self.timings),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            'unit': self.unit,
            'count': self.count,
            'iterations': self.iterations,
            'stats': self.stats,
            'extra': self.extra,
        }


def time_func(
    func: Callable,
    iterations: int,
    setup: Optional[Callable] = None,
    teardown: Optional[Callable] = None,
) -> List[float]:
    """Run func for `iterations` rounds, returning list of elapsed times."""
    timings = []
    for _ in range(iterations):
        if setup:
            setup()
        start = time.perf_counter()
        func()
        elapsed = time.perf_counter() - start
        timings.append(elapsed)
        if teardown:
            teardown()
    return timings

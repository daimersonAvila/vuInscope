"""Pure-Python discrete Markov chains (no numpy).

Used twice in the product:
  * vulnerability *lifecycle* (open -> in review -> mitigated -> closed), learned from history;
  * *attack path* risk model built from scan findings (see risk.py).
"""
from __future__ import annotations

import heapq
import math
import random
from typing import Dict, Iterable, List, Optional, Sequence


class MarkovChain:
    def __init__(self, states: Sequence[str]):
        self.states: List[str] = list(states)
        self.index: Dict[str, int] = {s: i for i, s in enumerate(self.states)}
        n = len(self.states)
        self.matrix: List[List[float]] = [[0.0] * n for _ in range(n)]

    # -- fitting ----------------------------------------------------------
    def train(self, sequences: Iterable[Sequence[str]]) -> int:
        """Count consecutive transitions, normalise rows. Returns number of transitions seen."""
        n = len(self.states)
        counts = [[0] * n for _ in range(n)]
        total = 0
        for seq in sequences:
            for a, b in zip(seq, seq[1:]):
                if a in self.index and b in self.index:
                    counts[self.index[a]][self.index[b]] += 1
                    total += 1
        for i in range(n):
            row_total = sum(counts[i])
            if row_total == 0:
                self.matrix[i] = [1.0 if j == i else 0.0 for j in range(n)]  # absorbing when unseen
            else:
                self.matrix[i] = [c / row_total for c in counts[i]]
        return total

    def load_matrix(self, matrix: Sequence[Sequence[float]]) -> None:
        n = len(self.states)
        if len(matrix) != n or any(len(r) != n for r in matrix):
            raise ValueError(f"matrix must be {n}x{n}")
        self.matrix = [list(r) for r in matrix]

    # -- queries ----------------------------------------------------------
    def probabilities_from(self, state: str) -> Dict[str, float]:
        self._check(state)
        row = self.matrix[self.index[state]]
        return {s: row[j] for j, s in enumerate(self.states)}

    def predict_next(self, state: str) -> str:
        probs = self.probabilities_from(state)
        return max(probs, key=probs.get)

    def simulate(self, start: str, steps: int, seed: Optional[int] = None) -> List[str]:
        self._check(start)
        rng = random.Random(seed)
        path, cur = [start], start
        for _ in range(steps):
            probs = self.probabilities_from(cur)
            cur = rng.choices(list(probs), weights=list(probs.values()), k=1)[0]
            path.append(cur)
        return path

    def expected_steps_to(self, start: str, target: str, max_iter: int = 50_000) -> Optional[float]:
        """Expected number of transitions to first hit `target`; None if it is not reached with certainty."""
        self._check(start)
        self._check(target)
        t, s = self.index[target], self.index[start]
        if s == t:
            return 0.0
        n = len(self.states)
        # every state reachable from start (without crossing target) must be able to reach target
        reach, stack = {s}, [s]
        while stack:
            u = stack.pop()
            for v in range(n):
                if self.matrix[u][v] > 0 and v != t and v not in reach:
                    reach.add(v)
                    stack.append(v)
        can_reach = self._can_reach(t)
        if any(u not in can_reach for u in reach):
            return None
        e = [0.0] * n
        for _ in range(max_iter):
            delta = 0.0
            for i in range(n):
                if i == t:
                    continue
                new = 1.0 + sum(self.matrix[i][j] * e[j] for j in range(n))
                delta = max(delta, abs(new - e[i]))
                e[i] = new
            if delta < 1e-10:
                break
        return e[s]

    def absorption_probability(self, start: str, target: str, absorbing: Sequence[str],
                               max_iter: int = 50_000) -> float:
        """P(chain started at `start` is absorbed in `target` before any other absorbing state)."""
        self._check(start)
        n = len(self.states)
        absorb = {self.index[a] for a in absorbing}
        t = self.index[target]
        h = [1.0 if i == t else 0.0 for i in range(n)]
        for _ in range(max_iter):
            delta = 0.0
            for i in range(n):
                if i in absorb:
                    continue
                new = sum(self.matrix[i][j] * h[j] for j in range(n))
                delta = max(delta, abs(new - h[i]))
                h[i] = new
            if delta < 1e-12:
                break
        return h[self.index[start]]

    def most_likely_path(self, start: str, target: str) -> Optional[List[str]]:
        """Highest-probability path (Dijkstra on -log p)."""
        self._check(start)
        self._check(target)
        dist = {start: 0.0}
        prev: Dict[str, str] = {}
        heap = [(0.0, start)]
        while heap:
            d, u = heapq.heappop(heap)
            if u == target:
                break
            if d > dist.get(u, math.inf):
                continue
            for j, p in enumerate(self.matrix[self.index[u]]):
                v = self.states[j]
                if p > 0 and v != u:
                    nd = d - math.log(p)
                    if nd < dist.get(v, math.inf):
                        dist[v], prev[v] = nd, u
                        heapq.heappush(heap, (nd, v))
        if target not in dist:
            return None
        path = [target]
        while path[-1] != start:
            path.append(prev[path[-1]])
        return path[::-1]

    def stationary_distribution(self, max_iter: int = 10_000) -> Dict[str, float]:
        n = len(self.states)
        dist = [1.0 / n] * n
        for _ in range(max_iter):
            new = [sum(dist[i] * self.matrix[i][j] for i in range(n)) for j in range(n)]
            diff = sum(abs(a - b) for a, b in zip(new, dist))
            dist = new
            if diff < 1e-12:
                break
        return {self.states[i]: dist[i] for i in range(n)}

    # -- helpers ----------------------------------------------------------
    def _can_reach(self, target_idx: int) -> set:
        n = len(self.states)
        seen, stack = {target_idx}, [target_idx]
        while stack:
            v = stack.pop()
            for u in range(n):
                if self.matrix[u][v] > 0 and u not in seen:
                    seen.add(u)
                    stack.append(u)
        return seen

    def _check(self, state: str) -> None:
        if state not in self.index:
            raise ValueError(f"Unknown state {state!r}. Expected one of {self.states}")

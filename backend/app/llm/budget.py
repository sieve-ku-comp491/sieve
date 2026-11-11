"""A spending limit for one run, checked before every LLM call (requirement N1)."""

import threading
from decimal import Decimal


class BudgetExceeded(Exception):
    def __init__(self, limit_usd: Decimal, committed_usd: Decimal, needed_usd: Decimal):
        left = limit_usd - committed_usd
        super().__init__(
            f"the next LLM call can cost up to ${needed_usd:.6f} and ${left:.6f} of the "
            f"${limit_usd:.2f} budget is left, so the run stops here"
        )
        self.limit_usd = limit_usd
        self.committed_usd = committed_usd
        self.needed_usd = needed_usd


class Reservation:
    """Money set aside for one call. Charge the real cost or release it when the call ends."""

    def __init__(self, budget: "Budget", amount_usd: Decimal):
        self._budget = budget
        self.amount_usd = amount_usd
        self.settled = False

    def charge(self, cost_usd: Decimal) -> None:
        self._budget._settle(self, cost_usd)

    def release(self) -> None:
        self._budget._settle(self, Decimal(0))


class Budget:
    def __init__(self, limit_usd: Decimal | str | int):
        self.limit_usd = Decimal(str(limit_usd))
        self.spent_usd = Decimal(0)
        self._reserved_usd = Decimal(0)
        self._lock = threading.Lock()

    @property
    def remaining_usd(self) -> Decimal:
        with self._lock:
            return self.limit_usd - self.spent_usd - self._reserved_usd

    def reserve(self, amount_usd: Decimal) -> Reservation:
        """Sets the worst-case cost aside, or raises BudgetExceeded if it doesn't fit."""
        with self._lock:
            committed = self.spent_usd + self._reserved_usd
            if committed + amount_usd > self.limit_usd:
                raise BudgetExceeded(self.limit_usd, committed, amount_usd)
            self._reserved_usd += amount_usd
        return Reservation(self, amount_usd)

    def _settle(self, reservation: Reservation, cost_usd: Decimal) -> None:
        with self._lock:
            if reservation.settled:
                raise RuntimeError("this reservation was already charged or released")
            reservation.settled = True
            self._reserved_usd -= reservation.amount_usd
            self.spent_usd += cost_usd

from decimal import Decimal

import pytest

from app.llm.budget import Budget, BudgetExceeded


def test_a_charge_replaces_the_reservation_with_the_real_cost():
    budget = Budget("1.00")
    reservation = budget.reserve(Decimal("0.40"))
    assert budget.remaining_usd == Decimal("0.60")

    reservation.charge(Decimal("0.10"))

    assert budget.spent_usd == Decimal("0.10")
    assert budget.remaining_usd == Decimal("0.90")


def test_a_reservation_that_does_not_fit_is_refused():
    budget = Budget("1.00")
    budget.reserve(Decimal("0.70"))

    with pytest.raises(BudgetExceeded) as raised:
        budget.reserve(Decimal("0.40"))

    assert raised.value.needed_usd == Decimal("0.40")
    assert "the run stops here" in str(raised.value)
    assert budget.remaining_usd == Decimal("0.30")


def test_releasing_gives_the_money_back():
    budget = Budget("1.00")
    budget.reserve(Decimal("0.70")).release()

    assert budget.spent_usd == 0
    assert budget.remaining_usd == Decimal("1.00")


def test_a_reservation_settles_only_once():
    reservation = Budget("1.00").reserve(Decimal("0.10"))
    reservation.charge(Decimal("0.05"))

    with pytest.raises(RuntimeError):
        reservation.release()


def test_a_call_that_costs_more_than_its_worst_case_is_reported(caplog):
    budget = Budget("1.00")

    budget.reserve(Decimal("0.10")).charge(Decimal("0.25"))

    assert budget.spent_usd == Decimal("0.25")
    assert "more than the worst case" in caplog.text

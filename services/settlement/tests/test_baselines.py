from pathlib import Path

from dots_settlement.engine import Store


def test_trailing_window(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.sqlite3")
    r = ("node-a", "node-b", "4477")
    for day, calls in ((1, 10), (2, 20), (3, 30), (9, 1000)):  # day 9 is after the period
        store.record_routes(f"2026-01-0{day}", {r: (calls, calls * 60, calls * 2, calls)})
    b = store.baselines("2026-01-05")[r]
    assert b.days == 3
    assert b.calls_per_day == 20
    assert b.acd == 60
    assert b.asr == 0.5
    # outside the 7-day window
    assert store.baselines("2026-01-20") == {}
    # re-recording a period replaces it (re-runs do not double count)
    store.record_routes("2026-01-03", {r: (30, 30 * 60, 60, 30)})
    assert store.baselines("2026-01-05")[r].calls_per_day == 20

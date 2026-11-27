from datetime import date

import pytest

from zeijaku_kakunin.matching.rank import decide_rank, rank_from_matrix

from conftest import TODAY, make_advisory


@pytest.mark.parametrize("cvss, exposure, expected", [
    (9.8, "internet", ("Rank-S", 3)),
    (9.0, "internal", ("Rank-A", 14)),
    (8.9, "internet", ("Rank-A", 14)),
    (7.0, "internal", ("Rank-B", 30)),
    (6.9, "internet", ("Rank-B", 30)),
    (4.0, "internal", ("Rank-C", 90)),
    (3.9, "internet", ("Rank-C", 90)),
    (None, "internet", ("Rank-C", 90)),
    (9.8, "未登録", ("Rank-A", 14)),      # 不明な公開区分は internal 扱い
])
def test_matrix(config, cvss, exposure, expected):
    assert rank_from_matrix(cvss, exposure, config) == expected


def test_advisory_values_take_priority(config):
    advisory = make_advisory(company_rank="Rank-S", deadline_days=5)
    rank, deadline, base = decide_rank(advisory, 2.0, "internal", config, TODAY)
    assert (rank, deadline, base) == ("Rank-S", date(2026, 11, 25), TODAY)


def test_partial_advisory_values(config):
    # ランクだけ指定: 日数はそのランクの既定値
    rank, deadline, _ = decide_rank(make_advisory(company_rank="Rank-B"), 9.8, "internet", config, TODAY)
    assert (rank, deadline) == ("Rank-B", date(2026, 12, 20))
    # 日数だけ指定: ランクは CVSS から
    rank, deadline, _ = decide_rank(make_advisory(deadline_days=7), 9.8, "internet", config, TODAY)
    assert (rank, deadline) == ("Rank-S", date(2026, 11, 27))


def test_deadline_counts_from_published_date(config):
    advisory = make_advisory(published_date=date(2026, 11, 1))
    rank, deadline, base = decide_rank(advisory, 9.8, "internet", config, TODAY)
    assert (rank, deadline, base) == ("Rank-S", date(2026, 11, 4), date(2026, 11, 1))


def test_no_advisory_uses_run_date(config):
    assert decide_rank(None, 7.5, "internal", config, TODAY) == ("Rank-B", date(2026, 12, 20), TODAY)

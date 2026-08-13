"""
©AngelaMos | 2026
test_runner.py
"""

import pytest

from bench.runner import (
    ALL_LAYERS,
    Ablation,
    Report,
    base_policy,
    format_report,
    load_corpus,
    run,
    run_ablation,
)
from not_sandboxed.context import Trust


MIN_PER_CLASS = 10

MAX_FALSE_POSITIVE_RATE = 0.05

MAX_HARD_FALSE_POSITIVE_RATE = 0.05

MIN_DETECTION_RATE = 0.90

HARD_BENIGN_CLASS = "benign_adversarial_data"

USER_BENIGN_CLASS = "benign_adversarial_user"


@pytest.fixture(scope = "module")
def report() -> Report:
    return run()


@pytest.fixture(scope = "module")
def ablation() -> dict[str, Ablation]:
    return run_ablation()


def test_corpus_has_both_halves() -> None:
    attacks, benign = load_corpus()

    assert attacks
    assert benign, "a detector with no benign corpus always says yes"


def test_every_class_has_enough_cases() -> None:
    attacks, benign = load_corpus()
    counts: dict[str, int] = {}
    for case in (*attacks, *benign):
        counts[case.label] = counts.get(case.label, 0) + 1

    thin = {k: v for k, v in counts.items() if v < MIN_PER_CLASS}

    assert thin == {}, f"classes too small to mean anything: {thin}"


def test_benign_corpus_covers_both_span_kinds() -> None:
    _, benign = load_corpus()
    labels = {case.label for case in benign}

    assert USER_BENIGN_CLASS in labels
    assert HARD_BENIGN_CLASS in labels


def test_the_hard_benign_class_sits_where_ingress_actually_runs() -> None:
    _, benign = load_corpus()
    hard = [case for case in benign if case.label == HARD_BENIGN_CLASS]

    assert hard
    assert all(case.span == Trust.DATA for case in hard), (
        "ingress skips every span that is not DATA, so an "
        "adversarially-benign class in a USER span measures a "
        "`continue` statement and always reports 0.0%"
    )


def test_the_user_benign_class_proves_the_data_scoping() -> None:
    _, benign = load_corpus()
    user = [case for case in benign if case.label == USER_BENIGN_CLASS]

    assert user
    assert all(case.span == Trust.USER for case in user)


def test_every_layer_is_load_bearing(
    ablation: dict[str,
                   Ablation],
) -> None:
    inert = [layer for layer, result in ablation.items() if result.inert]

    assert inert == [], (
        f"inert layers must be deleted, not tolerated: {inert}"
    )


def test_ablation_covers_every_layer(
    ablation: dict[str,
                   Ablation],
) -> None:
    assert set(ablation) == set(ALL_LAYERS)


def test_alibied_layers_are_reported_not_hidden(
    ablation: dict[str,
                   Ablation],
) -> None:
    alibied = [
        layer for layer, result in ablation.items() if result.alibied
    ]

    for layer in alibied:
        assert ablation[layer].solo > 0


def test_false_positive_rate_is_reported_and_low(
    report: Report,
) -> None:
    assert report.false_positive_rate <= MAX_FALSE_POSITIVE_RATE


def test_the_hard_benign_class_has_its_own_floor(
    report: Report,
) -> None:
    rate = report.class_false_positive_rate(HARD_BENIGN_CLASS)

    assert rate <= MAX_HARD_FALSE_POSITIVE_RATE, (
        f"legitimate retrieved content blocks at {rate * 100:.1f}%; "
        "the pooled rate hides this because three benign classes are "
        "easy"
    )


def test_detection_rate_meets_the_floor(report: Report) -> None:
    assert report.detection_rate >= MIN_DETECTION_RATE


def test_report_states_who_wrote_the_corpus(
    report: Report,
    ablation: dict[str,
                   Ablation],
) -> None:
    text = format_report(report, ablation)

    assert "written by the same author as the rules" in text
    assert "false positive rate" in text


def test_report_separates_the_hard_benign_rate_from_the_pooled_one(
    report: Report,
    ablation: dict[str,
                   Ablation],
) -> None:
    text = format_report(report, ablation)

    assert "FPR on hard benign" in text
    assert HARD_BENIGN_CLASS in text


def test_disabling_everything_catches_almost_nothing() -> None:
    off = {f"{layer}_enabled": False for layer in ALL_LAYERS}
    naked = run(base_policy(**off))

    assert naked.detection_rate == 0.0

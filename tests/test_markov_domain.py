from vulnscope.domain.markov import MarkovChain
from vulnscope.domain.risk import build_risk_model


def test_expected_steps_and_unreachable():
    c = MarkovChain(["a", "b", "c"])
    c.load_matrix([[0.5, 0.5, 0], [0, 0.5, 0.5], [0, 0, 1]])
    assert abs(c.expected_steps_to("a", "c") - 4.0) < 1e-6
    c.load_matrix([[0.5, 0.5, 0], [0, 1, 0], [0, 0, 1]])
    assert c.expected_steps_to("a", "c") is None


def test_absorption_and_path():
    c = MarkovChain(["s", "win", "lose"])
    c.load_matrix([[0, 0.3, 0.7], [0, 1, 0], [0, 0, 1]])
    assert abs(c.absorption_probability("s", "win", ["win", "lose"]) - 0.3) < 1e-9
    assert c.most_likely_path("s", "win") == ["s", "win"]


def test_train_normalises():
    c = MarkovChain(["a", "b"])
    assert c.train([["a", "b", "b"], ["a", "b"]]) == 3
    assert abs(sum(c.matrix[0]) - 1) < 1e-9 and c.matrix[0][1] == 1.0


def test_risk_monotonic():
    f = lambda sev, cat: {"severity": sev, "category": cat}
    assert build_risk_model([])["score"] == 0
    low = build_risk_model([f("low", "exposure")])["score"]
    mid = build_risk_model([f("high", "injection")])["score"]
    hi = build_risk_model([f("critical", "secrets")] * 3 + [f("critical", "execution")] * 3)["score"]
    assert 0 < low < mid < hi <= 100

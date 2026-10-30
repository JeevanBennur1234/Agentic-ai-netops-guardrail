import netops_guardrail.testbed.live_connectivity as checker


def test_connectivity_checker_checks_both_directions(monkeypatch):
    ping_calls = []
    monkeypatch.setattr(checker, "_host_shell_pid", lambda name: {"h1": 101, "h2": 202}[name])
    monkeypatch.setattr(checker, "_host_ip", lambda pid: {101: "10.0.0.1", 202: "10.0.0.2"}[pid])

    def fake_ping(pid, destination):
        ping_calls.append((pid, destination))
        return True

    monkeypatch.setattr(checker, "_can_ping", fake_ping)
    assert checker.check_host_connectivity() is True
    assert ping_calls == [(101, "10.0.0.2"), (202, "10.0.0.1")]


def test_connectivity_checker_fails_closed_when_host_missing(monkeypatch):
    def missing(_name):
        raise RuntimeError("not running")
    monkeypatch.setattr(checker, "_host_shell_pid", missing)
    assert checker.check_host_connectivity() is False

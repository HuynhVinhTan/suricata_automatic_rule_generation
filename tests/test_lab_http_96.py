"""Fully mocked synthetic services: the lab client never reaches the network in CI."""
from urllib.parse import urlsplit

import pytest

from scripts import lab_http_96


class FakeResponse:
    status = 200

    def __init__(self, port, path, bad=False):
        self.port, self.path, self.bad = port, path, bad

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        if self.bad:
            return b"INCORRECT"
        return (
            "SYNTHETIC LAB SERVICE\n"
            f"SERVICE_PORT={self.port}\n"
            f"REQUESTED_PATH={self.path}\n"
        ).encode()


class FakeOpener:
    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at

    def open(self, request, timeout):
        assert timeout == 5
        url = urlsplit(request.full_url)
        assert url.hostname == "192.168.10.10"
        assert 18100 <= url.port <= 18111
        assert request.get_header("Connection") == "close"
        self.calls.append((url.port, url.path))
        return FakeResponse(url.port, url.path, len(self.calls) == self.fail_at)


@pytest.mark.parametrize("scenario", ["recon-v03", "matched12-v02"])
def test_96_get_scenario_success(scenario, capsys):
    client = FakeOpener()
    slept = []
    result = lab_http_96.execute(scenario, opener=client,
                                  sleep=slept.append, interval=0.6)
    assert result["status"] == "PASS"
    assert result["http_success"] == 96
    assert result["http_failures"] == 0
    assert len(client.calls) == 96
    assert len(slept) == 95
    assert set(result["success_by_port"].values()) == {8}
    if scenario == "recon-v03":
        assert set(result["success_by_path"].values()) == {24}
        assert set(result["success_by_path"]) == set(lab_http_96.PATHS)
    else:
        assert result["success_by_path"] == {"/health": 96}
    assert "SAFE_TO_STOP_CAPTURE: YES" in capsys.readouterr().out


def test_one_bad_response_never_signals_safe_to_stop(capsys):
    result = lab_http_96.execute("recon-v03", opener=FakeOpener(fail_at=96),
                                  sleep=lambda _: None)
    assert result["status"] == "FAIL"
    assert result["http_success"] == 95
    assert result["http_failures"] == 1
    assert "SAFE_TO_STOP_CAPTURE: NO" in capsys.readouterr().out


def test_only_preapproved_scenarios_are_allowed():
    with pytest.raises(ValueError):
        lab_http_96.plan("external-scan")
    with pytest.raises(ValueError):
        lab_http_96.execute("recon-v03", opener=FakeOpener(),
                            sleep=lambda _: None, interval=-1)

from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "demo" / "vm2-capture-session.sh"


def test_capture_workflow_is_bounded_and_bidirectional():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "MAX_SECONDS=120" in text
    assert "MAX_PACKETS=5000" in text
    assert "SNAPLEN=96" in text
    assert 'sudo tcpdump' in text
    assert "listening on $IFACE" in text
    assert "dst portrange 18100-18123" in text
    assert "src portrange 18100-18123" in text
    assert "mv -- \"$PARTIAL\" \"$OUT\"" in text
    assert "refusing to overwrite" in text


def test_capture_workflow_has_no_privilege_fallback_or_unrestricted_filter():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "getcap" not in text
    assert "setcap" not in text
    assert "sudoers" in text
    assert "host 192.168.10.10 and host 192.168.10.20" not in text
    assert "src host 192.168.10.20 and dst host 192.168.10.10" in text
    assert "src host 192.168.10.10 and dst host 192.168.10.20" in text

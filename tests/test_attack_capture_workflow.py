from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "demo" / "vm2-capture-session.sh"


def test_capture_workflow_is_bounded_and_bidirectional():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "MAX_SECONDS=120" in text
    assert "MAX_PACKETS=5000" in text
    assert "SNAPLEN=96" in text
    assert "sudo -v" in text
    assert "sudo sh -c" in text
    assert "exec setsid --wait sh -c" in text
    assert "setsid --wait sudo -n tcpdump" not in text
    assert "listening on $IFACE" in text
    assert "dst portrange 18100-18123" in text
    assert "src portrange 18100-18123" in text
    assert "mv -- \"$PARTIAL\" \"$OUT\"" in text
    assert "refusing to overwrite" in text


def test_capture_workflow_has_no_privilege_fallback_or_unrestricted_filter():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "getcap" not in text
    assert "setcap" not in text
    assert "setsid --wait" in text
    assert "kill -KILL -- \"-$CAPTURE_PGID\"" in text
    assert "host 192.168.10.10 and host 192.168.10.20" not in text
    assert "src host 192.168.10.20 and dst host 192.168.10.10" in text
    assert "src host 192.168.10.10 and dst host 192.168.10.20" in text

"""Offline checksum regression tests with synthesized classic PCAP frames."""
import hashlib
import struct

import pytest

from scripts import pcap_checksum_normalize as tool


CLIENT = bytes((192, 168, 10, 20))
SERVER = bytes((192, 168, 10, 10))


def frame(source, target, *, flags, payload=b"", valid=True):
    tcp = bytearray(
        struct.pack("!HHIIBBHHH", 50000 if source == CLIENT else 18100,
                    18100 if source == CLIENT else 50000,
                    1, 0, 0x50, flags, 8192, 0, 0) + payload
    )
    pseudo = source + target + b"\0\x06" + struct.pack("!H", len(tcp))
    checksum = tool.checksum(pseudo + tcp)
    struct.pack_into("!H", tcp, 16, checksum if valid else 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                     0, 0x4000, 64, 6, 0, source, target)
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp


def sample():
    frames = [
        frame(CLIENT, SERVER, flags=0x02),
        frame(SERVER, CLIENT, flags=0x12, valid=False),
        frame(CLIENT, SERVER, flags=0x18,
              payload=b"GET /admin HTTP/1.1\r\n\r\n"),
    ]
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for i, packet in enumerate(frames):
        out.extend(struct.pack("<IIII", i + 1, 0, len(packet), len(packet)))
        out.extend(packet)
    return bytes(out)


def args(tmp_path):
    original = tmp_path / "recon-v03.pcap"
    original.write_bytes(sample())
    return dict(
        pcap=original,
        output=tmp_path / "recon-v03-checksum-normalized.pcap",
        expected_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
        source_ipv4="192.168.10.20",
        destination_ipv4="192.168.10.10",
        expected_syn=1, expected_get=1, expected_bad_outbound=None,
        execute=False,
    )


def test_normalizer_dry_run_and_provenance(tmp_path):
    kwargs = args(tmp_path)
    raw = kwargs["pcap"].read_bytes()
    dry = tool.normalize(**kwargs)
    assert dry["status"] == "dry_run"
    assert dry["outbound_bad_before"] == 1
    assert dry["outbound_repaired"] == 1
    assert dry["inbound_bad"] == 0
    assert dry["bad_after"] == 0
    assert not kwargs["output"].exists()
    kwargs["execute"] = True
    with pytest.raises(tool.PCAPError, match="expected-bad-outbound"):
        tool.normalize(**kwargs)
    kwargs["expected_bad_outbound"] = 1
    result = tool.normalize(**kwargs)
    assert result["status"] == "succeeded"
    assert kwargs["output"].exists()
    assert result["derived_sha256"] == hashlib.sha256(
        kwargs["output"].read_bytes()
    ).hexdigest()
    assert kwargs["pcap"].read_bytes() == raw
    assert kwargs["output"].with_suffix(".pcap.provenance.json").exists()
    with pytest.raises(tool.PCAPError, match="exists"):
        tool.normalize(**kwargs)


def test_inbound_checksum_error_is_never_repaired():
    raw = sample()
    corrupted = bytearray(raw)
    # Flip one byte in the first (inbound) SYN TCP checksum field.
    first_tcp_pos = 24 + 16 + 14 + 20
    corrupted[first_tcp_pos + 16] ^= 0x01
    with pytest.raises(tool.PCAPError, match="inbound"):
        tool.inspect_and_derive(bytes(corrupted), "192.168.10.20", "192.168.10.10")


def test_truncation_rejected():
    raw = bytearray(sample())
    included = struct.unpack_from("<I", raw, 24 + 8)[0]
    struct.pack_into("<I", raw, 24 + 12, included + 1)
    with pytest.raises(tool.PCAPError, match="Truncated"):
        tool.inspect_and_derive(bytes(raw), "192.168.10.20", "192.168.10.10")


def test_count_mismatch_does_not_write(tmp_path):
    kwargs = args(tmp_path)
    kwargs["execute"] = True
    kwargs["expected_bad_outbound"] = 1
    kwargs["expected_syn"] = 96
    with pytest.raises(tool.PCAPError, match="count"):
        tool.normalize(**kwargs)
    assert not kwargs["output"].exists()

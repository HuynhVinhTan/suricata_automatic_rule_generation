"""Input and plan safety tests for private-lab traffic generators."""

import pytest

from scripts import lab_normal_service_access as normal
from scripts import lab_slow_port_scan as scan


def test_scan_requires_exactly_24_unique_ports_and_private_target():
    ports = ",".join(str(port) for port in range(18100, 18124))
    assert len(scan._ports(ports)) == 24
    with pytest.raises(ValueError):
        scan._ports(",".join(str(port) for port in range(18100, 18123)))
    with pytest.raises(ValueError):
        scan._lab_ip("192.168.206.131")


def test_normal_plan_rejects_more_than_two_negative_controls():
    with pytest.raises(ValueError):
        normal.run(
            run_id="normal-test",
            target="192.168.10.10",
            open_port=18080,
            closed_ports=[18100, 18101, 18102],
            interval_seconds=0.001,
        )


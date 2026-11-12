"""Additive signing-run directory safety; preserve previous unsigned evidence."""

import pytest

from netids import trusted_replay


def test_existing_unsigned_replay_evidence_is_preserved_and_new_run_is_unique(
    tmp_path, monkeypatch,
):
    root = tmp_path / "isolated-lifecycle-9103003"
    evidence = root / "replay-evidence"
    old_case = evidence / "worker-attack-holdout-01-20261111"
    old_case.mkdir(parents=True)
    old_eve = old_case / "eve.json"
    old_eve.write_text('{"event_type":"alert","alert":{"signature_id":9103003}}\n')
    original_bytes = old_eve.read_bytes()

    ids = iter(("a" * 32, "b" * 32))
    monkeypatch.setattr(trusted_replay.secrets, "token_hex", lambda n: next(ids))

    first_id, first = trusted_replay.create_exclusive_replay_run_dir(root)
    second_id, second = trusted_replay.create_exclusive_replay_run_dir(root)

    assert first_id == "a" * 32
    assert second_id == "b" * 32
    assert first != second
    assert first.is_dir() and second.is_dir()
    assert old_eve.read_bytes() == original_bytes
    assert old_case.is_dir()


def test_signing_run_never_reuses_existing_random_id(tmp_path, monkeypatch):
    root = tmp_path / "isolated-lifecycle-9103003"
    monkeypatch.setattr(trusted_replay.secrets, "token_hex", lambda n: "c" * 32)
    _, first = trusted_replay.create_exclusive_replay_run_dir(root)
    with pytest.raises(trusted_replay.ReplayGateError, match="collision"):
        trusted_replay.create_exclusive_replay_run_dir(root)
    assert first.is_dir()


def test_existing_non_directory_evidence_path_is_rejected(tmp_path):
    root = tmp_path / "isolated-lifecycle-9103003"
    root.mkdir()
    (root / "replay-evidence").write_text("preserve me")
    with pytest.raises(trusted_replay.ReplayGateError, match="not a directory"):
        trusted_replay.create_exclusive_replay_run_dir(root)
    assert (root / "replay-evidence").read_text() == "preserve me"


def test_symlinked_evidence_root_is_rejected(tmp_path):
    root = tmp_path / "isolated-lifecycle-9103003"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (root / "replay-evidence").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("Symlink creation is unavailable")
    with pytest.raises(trusted_replay.ReplayGateError, match="Symlink"):
        trusted_replay.create_exclusive_replay_run_dir(root)

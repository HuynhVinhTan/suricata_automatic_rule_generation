"""Small, fail-closed primitives for the G5 root/operator split."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

try:
    import grp
except ModuleNotFoundError:  # pragma: no cover - Windows has no POSIX group database.
    class _MissingGroupDatabase:
        @staticmethod
        def getgrnam(_name):
            raise KeyError(_name)

        @staticmethod
        def getgrall():
            return ()

    grp = _MissingGroupDatabase()

try:
    import pwd
except ModuleNotFoundError:  # pragma: no cover - Windows has no POSIX passwd database.
    class _MissingPasswordDatabase:
        @staticmethod
        def getpwnam(_name):
            raise KeyError(_name)

    pwd = _MissingPasswordDatabase()


SERVICE_USER = "suricata-g5"
SERVICE_GROUP = "suricata-g5"
SERVICE_UID = 999
SERVICE_GID = 982


class PrivilegeSeparationError(RuntimeError):
    """A required privilege, identity, or ACL invariant was not proven."""


@dataclass(frozen=True)
class ServiceAccount:
    username: str
    uid: int
    gid: int
    group_name: str
    shell: str
    home: str


@dataclass(frozen=True)
class ProcIdentity:
    uid: int
    gid: int
    groups: tuple[int, ...]
    state: str


@dataclass(frozen=True)
class AttemptAccessPaths:
    attempt_root: Path
    runtime_dir: Path
    rules_dir: Path
    active_rules: Path
    logs_dir: Path
    effective_config: Path
    referenced_files: tuple[Path, ...] = ()


def require_root_operator() -> None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        raise PrivilegeSeparationError("root operator with EUID 0 is required")


def require_root_operator_if_supported() -> None:
    """Reject non-root POSIX operators while keeping offline Windows tests portable."""
    if hasattr(os, "geteuid"):
        require_root_operator()


def lookup_service_account(
    username: str = SERVICE_USER, group_name: str = SERVICE_GROUP,
) -> ServiceAccount:
    try:
        user = pwd.getpwnam(username)
        group = grp.getgrnam(group_name)
    except (KeyError, OSError) as exc:
        raise PrivilegeSeparationError("dedicated Suricata service account is unavailable") from exc
    shell = str(getattr(user, "pw_shell", ""))
    home = str(getattr(user, "pw_dir", ""))
    if (
        getattr(user, "pw_name", None) != username
        or getattr(group, "gr_name", None) != group_name
        or getattr(user, "pw_uid", None) != SERVICE_UID
        or getattr(user, "pw_gid", None) != SERVICE_GID
        or getattr(group, "gr_gid", None) != SERVICE_GID
        or shell not in ("/usr/sbin/nologin", "/sbin/nologin")
        or home not in ("", "/nonexistent", "/var/empty")
    ):
        raise PrivilegeSeparationError("dedicated Suricata service account identity is unsafe")
    for supplementary in getattr(grp, "getgrall", lambda: ())():
        if getattr(supplementary, "gr_gid", None) == 0 and username in getattr(supplementary, "gr_mem", ()):
            raise PrivilegeSeparationError("service account has supplementary root group")
    return ServiceAccount(username, SERVICE_UID, SERVICE_GID, group_name, shell, home)


def _run_setfacl(argv: list[str], *, runner=subprocess.run) -> None:
    try:
        result = runner(
            argv, capture_output=True, text=True, timeout=30, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PrivilegeSeparationError("ACL application failed") from exc
    if result.returncode != 0:
        raise PrivilegeSeparationError(
            "ACL application failed: " + str(getattr(result, "stderr", ""))[:512]
        )


def _access_specs(paths: AttemptAccessPaths, username: str) -> tuple[tuple[str, Path], ...]:
    return (
        ("--x", Path(paths.attempt_root)),
        ("-wx", Path(paths.runtime_dir)),
        ("--x", Path(paths.rules_dir)),
        ("r--", Path(paths.active_rules)),
        ("-wx", Path(paths.logs_dir)),
        ("r--", Path(paths.effective_config)),
        *(("r--", Path(path)) for path in paths.referenced_files),
    )


def apply_attempt_acls(
    paths: AttemptAccessPaths, *, username: str = SERVICE_USER, runner=subprocess.run,
) -> None:
    """Grant only the attempt files needed by the Suricata child."""
    for permission, path in _access_specs(paths, username):
        if not path.exists():
            if path == paths.active_rules:
                continue
            raise PrivilegeSeparationError(f"ACL target is missing: {path}")
        _run_setfacl(["setfacl", "-m", f"u:{username}:{permission}", str(path)], runner=runner)


def remove_attempt_acls(
    paths: AttemptAccessPaths, *, username: str = SERVICE_USER, runner=subprocess.run,
) -> None:
    """Remove only ACL entries previously scoped to this attempt."""
    for _permission, path in _access_specs(paths, username):
        if path.exists():
            _run_setfacl(["setfacl", "-x", f"u:{username}", str(path)], runner=runner)


def atomic_replace_with_acl(
    path: Path, data: bytes, *, username: str = SERVICE_USER, runner=subprocess.run,
) -> None:
    """Atomically replace active.rules, then restore the child's read ACL."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".isolated-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        _run_setfacl(["setfacl", "-m", f"u:{username}:r--", str(path)], runner=runner)
    finally:
        Path(name).unlink(missing_ok=True)


def apply_active_rules_acl(
    path: Path, *, username: str = SERVICE_USER, runner=subprocess.run,
) -> None:
    path = Path(path)
    if not path.is_file():
        raise PrivilegeSeparationError(f"active.rules is missing: {path}")
    _run_setfacl(["setfacl", "-m", f"u:{username}:r--", str(path)], runner=runner)


def ensure_root_owned_audit(path: Path) -> None:
    """Check persistent audit ownership/mode without changing either."""
    if not hasattr(os, "geteuid"):
        return
    require_root_operator()
    path = Path(path)
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_stat = parent.stat()
    if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o077:
        raise PrivilegeSeparationError("persistent audit directory is not root-only")
    if path.exists():
        stat = path.stat()
        if stat.st_uid != 0 or stat.st_mode & 0o077:
            raise PrivilegeSeparationError("persistent audit is not root-owned and root-only")


def referenced_configuration_files(configuration: dict, config_path: Path) -> tuple[Path, ...]:
    """Resolve every external config/rules include without granting directory read access."""
    if not isinstance(configuration, dict):
        raise PrivilegeSeparationError("effective YAML is not an object")
    config_path = Path(config_path).resolve()
    values: list[tuple[object, Path]] = []
    default_rule_path = Path(str(configuration.get("default-rule-path", config_path.parent)))
    if not default_rule_path.is_absolute():
        default_rule_path = config_path.parent / default_rule_path
    for key in ("classification-file", "reference-config-file", "threshold-file"):
        if configuration.get(key):
            values.append((configuration[key], config_path.parent))
    for key in ("include", "includes"):
        raw = configuration.get(key, ())
        if isinstance(raw, str):
            raw = (raw,)
        if isinstance(raw, (list, tuple)):
            values.extend((item, config_path.parent) for item in raw)
    raw_rules = configuration.get("rule-files", ())
    if isinstance(raw_rules, str):
        raw_rules = (raw_rules,)
    if isinstance(raw_rules, (list, tuple)):
        values.extend((item, default_rule_path) for item in raw_rules if item != "active.rules")
    result: list[Path] = []
    for raw, base in values:
        if not isinstance(raw, str) or not raw.strip():
            raise PrivilegeSeparationError("effective YAML contains an invalid external reference")
        path = Path(raw)
        path = path if path.is_absolute() else Path(base) / path
        resolved = path.resolve()
        if resolved not in result:
            result.append(resolved)
    return tuple(result)


_STATUS_VALUE = re.compile(r"^(Uid|Gid|Groups|State):\s*(.*)$")


def verify_proc_identity_text(status_text: str) -> ProcIdentity:
    values: dict[str, str] = {}
    for line in str(status_text).splitlines():
        match = _STATUS_VALUE.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    try:
        uids = tuple(int(value) for value in values["Uid"].split())
        gids = tuple(int(value) for value in values["Gid"].split())
        groups = tuple(int(value) for value in values.get("Groups", "").split())
    except (KeyError, ValueError) as exc:
        raise PrivilegeSeparationError("unable to parse Suricata /proc identity") from exc
    if (
        len(uids) < 4 or any(uid != SERVICE_UID for uid in uids)
        or len(gids) < 4 or any(gid != SERVICE_GID for gid in gids)
        or 0 in groups
        or not groups
        or values.get("State", "").startswith("Z")
    ):
        raise PrivilegeSeparationError("Suricata process identity or supplementary root group is unsafe")
    return ProcIdentity(SERVICE_UID, SERVICE_GID, groups, values["State"])


def verify_process_identity(
    pid: int, *, proc_root: Path = Path("/proc"), expected_uid: int = SERVICE_UID,
    expected_gid: int = SERVICE_GID,
) -> ProcIdentity:
    if pid <= 0:
        raise PrivilegeSeparationError("invalid Suricata PID")
    try:
        status_text = (Path(proc_root) / str(pid) / "status").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PrivilegeSeparationError("Suricata /proc status is unavailable") from exc
    identity = verify_proc_identity_text(status_text)
    if identity.uid != expected_uid or identity.gid != expected_gid:
        raise PrivilegeSeparationError("Suricata process identity mismatch")
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError) as exc:
        raise PrivilegeSeparationError("Suricata process is not alive") from exc
    return identity


def verify_attempt_socket_path(path: Path, attempt_root: Path) -> None:
    path = Path(path)
    root = Path(attempt_root).resolve()
    if path.is_symlink() or path.resolve().parent != (root / "runtime").resolve():
        raise PrivilegeSeparationError("Suricata control socket is outside the expected attempt")
    if path.exists() and not stat.S_ISSOCK(path.stat().st_mode):
        raise PrivilegeSeparationError("Suricata control path is not a UNIX socket")

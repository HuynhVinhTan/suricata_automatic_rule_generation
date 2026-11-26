"""Small, fail-closed primitives for the G5 root/operator split."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

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
    uid_fields: tuple[int, ...]
    gid_fields: tuple[int, ...]
    groups: tuple[int, ...]
    state: str

    @property
    def uid(self) -> int:
        return self.uid_fields[0]

    @property
    def gid(self) -> int:
        return self.gid_fields[0]

    @property
    def all_root(self) -> bool:
        return bool(self.uid_fields) and all(uid == 0 for uid in self.uid_fields) and all(
            gid == 0 for gid in self.gid_fields
        )

    def is_expected(self, uid: int = SERVICE_UID, gid: int = SERVICE_GID) -> bool:
        return (
            len(self.uid_fields) == 4
            and len(self.gid_fields) == 4
            and all(value == uid for value in self.uid_fields)
            and all(value == gid for value in self.gid_fields)
            and bool(self.groups)
            and 0 not in self.groups
        )


@dataclass(frozen=True)
class AttemptAccessPaths:
    attempt_root: Path
    runtime_dir: Path
    rules_dir: Path
    active_rules: Path
    logs_dir: Path
    effective_config: Path
    referenced_files: tuple[Path, ...] = ()


@dataclass(frozen=True)
class AclMutation:
    path: Path
    selector: str
    previous_entry: str | None


class AclTransaction:
    """Records only this attempt's ACL mutations and reverses them safely."""

    def __init__(self, *, runner=subprocess.run):
        self.runner = runner
        self.mutations: list[AclMutation] = []
        self.rollback_attempted = False
        self.rolled_back = False

    def add(self, path: Path, selector: str, previous_entry: str | None) -> None:
        if any(mutation.path == path and mutation.selector == selector for mutation in self.mutations):
            return
        self.mutations.append(AclMutation(Path(path), selector, previous_entry))

    def rollback(self) -> None:
        if self.rollback_attempted:
            if self.rolled_back:
                return
            raise PrivilegeSeparationError("ACL rollback previously failed")
        self.rollback_attempted = True
        failures = []
        for mutation in reversed(self.mutations):
            try:
                if mutation.previous_entry is None:
                    _run_setfacl(
                        ["setfacl", "-x", mutation.selector, str(mutation.path)],
                        runner=self.runner, error_prefix="ACL rollback failed",
                    )
                else:
                    _run_setfacl(
                        ["setfacl", "-m", mutation.previous_entry, str(mutation.path)],
                        runner=self.runner, error_prefix="ACL rollback failed",
                    )
                if _existing_acl_entry(
                    mutation.path, mutation.selector, runner=self.runner,
                ) != mutation.previous_entry:
                    raise PrivilegeSeparationError(
                        f"ACL rollback verification failed for {mutation.path}"
                    )
            except PrivilegeSeparationError as exc:
                failures.append(str(exc))
        self.rolled_back = not failures
        if failures:
            raise PrivilegeSeparationError("ACL rollback failed: " + "; ".join(failures)[:512])


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


def _run_setfacl(
    argv: list[str], *, runner=subprocess.run, error_prefix="ACL application failed",
) -> None:
    try:
        result = runner(
            argv, capture_output=True, text=True, timeout=30, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PrivilegeSeparationError(error_prefix) from exc
    if result.returncode != 0:
        raise PrivilegeSeparationError(error_prefix + ": " + str(getattr(result, "stderr", ""))[:512])


def _access_specs(paths: AttemptAccessPaths, username: str) -> tuple[tuple[str, Path], ...]:
    root = Path(paths.attempt_root).resolve()
    specs = [
        ("--x", Path(paths.attempt_root)),
        ("-wx", Path(paths.runtime_dir)),
        ("--x", Path(paths.rules_dir)),
        ("r--", Path(paths.active_rules)),
        ("-wx", Path(paths.logs_dir)),
        ("r--", Path(paths.effective_config)),
    ]
    for reference in paths.referenced_files:
        reference = Path(reference)
        parent = reference.parent
        while parent != root:
            if not parent.is_relative_to(root):
                raise PrivilegeSeparationError("referenced ACL directory is outside the current attempt")
            specs.append(("--x", parent))
            parent = parent.parent
        specs.append(("r--", reference))
    deduplicated = []
    seen = set()
    for permission, path in specs:
        key = (permission, Path(path))
        if key not in seen:
            seen.add(key)
            deduplicated.append((permission, Path(path)))
    return tuple(deduplicated)


_PROTECTED_ROOTS = tuple(
    Path(path) for path in (
        "/etc/suricata", "/var/lib/suricata", "/var/log/suricata",
        "/run/suricata", "/var/run/suricata",
    )
)


def _protected(path: Path) -> bool:
    resolved = Path(path).resolve()
    return any(resolved == root or resolved.is_relative_to(root) for root in _PROTECTED_ROOTS)


def _validate_acl_targets(paths: AttemptAccessPaths, username: str) -> None:
    if Path(paths.attempt_root).is_symlink():
        raise PrivilegeSeparationError("ACL target is missing or symlinked")
    root = Path(paths.attempt_root).resolve()
    if _protected(root):
        raise PrivilegeSeparationError("ACL target overlaps protected Suricata path")
    for _permission, path in _access_specs(paths, username):
        path = Path(path)
        if path == paths.active_rules and not path.exists():
            continue
        _reject_symlink_components(path)
        if path.is_symlink() or not path.exists():
            raise PrivilegeSeparationError(f"ACL target is missing or symlinked: {path}")
        resolved = path.resolve()
        if not resolved.is_relative_to(root) or _protected(resolved):
            raise PrivilegeSeparationError("ACL target is outside the current attempt")


def _existing_acl_entry(path: Path, selector: str, *, runner=subprocess.run) -> str | None:
    try:
        result = runner(
            ["getfacl", "--absolute-names", "-cp", str(path)],
            capture_output=True, text=True, timeout=30, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PrivilegeSeparationError("ACL inspection failed") from exc
    if result.returncode != 0:
        raise PrivilegeSeparationError(
            "ACL inspection failed: " + str(getattr(result, "stderr", ""))[:512]
        )
    prefix = selector + ":"
    return next((line for line in result.stdout.splitlines() if line.startswith(prefix)), None)


def apply_attempt_acls(
    paths: AttemptAccessPaths, *, username: str = SERVICE_USER, runner=subprocess.run,
) -> AclTransaction:
    """Grant only the attempt files needed by the Suricata child."""
    _validate_acl_targets(paths, username)
    transaction = AclTransaction(runner=runner)
    try:
        for permission, path in _access_specs(paths, username):
            if path == paths.active_rules and not path.exists():
                continue
            selector = f"user:{username}"
            previous = _existing_acl_entry(path, selector, runner=runner)
            _run_setfacl(
                ["setfacl", "-m", f"{selector}:{permission}", str(path)], runner=runner,
            )
            transaction.add(path, selector, previous)
    except PrivilegeSeparationError as exc:
        try:
            transaction.rollback()
        except PrivilegeSeparationError as rollback_exc:
            raise PrivilegeSeparationError(
                f"ACL application failed; ACL rollback failed: {rollback_exc}"
            ) from exc
        raise PrivilegeSeparationError(f"ACL application failed: {exc}") from exc
    return transaction


def remove_attempt_acls(
    paths: AttemptAccessPaths, *, username: str = SERVICE_USER, runner=subprocess.run,
    transaction: AclTransaction | None = None,
) -> None:
    """Remove only ACL entries previously scoped to this attempt."""
    if transaction is None:
        raise PrivilegeSeparationError("ACL transaction is required for cleanup")
    transaction.rollback()


def atomic_replace_with_acl(
    path: Path, data: bytes, *, username: str = SERVICE_USER, runner=subprocess.run,
    transaction: AclTransaction | None = None,
) -> None:
    """Atomically replace active.rules, then restore the child's read ACL."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = _existing_acl_entry(path, f"user:{username}", runner=runner) if path.exists() else None
    fd, name = tempfile.mkstemp(prefix=".isolated-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        _run_setfacl(["setfacl", "-m", f"u:{username}:r--", str(path)], runner=runner)
        if transaction is not None:
            transaction.add(path, f"user:{username}", previous)
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


def _reject_symlink_components(path: Path) -> None:
    for component in (Path(path), *Path(path).parents):
        if component.is_symlink():
            raise PrivilegeSeparationError("effective YAML reference is a symlink")


def _resolve_reference(raw: object, base: Path, allowed: Path) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise PrivilegeSeparationError("effective YAML contains an invalid external reference")
    path = Path(raw)
    path = path if path.is_absolute() else Path(base) / path
    _reject_symlink_components(path)
    resolved = path.resolve()
    if _protected(resolved) or not resolved.is_relative_to(allowed):
        raise PrivilegeSeparationError("effective YAML reference escapes the isolated root")
    if not resolved.is_file():
        raise PrivilegeSeparationError("effective YAML reference is not a regular file")
    return resolved


def _resolve_reference_directory(raw: object, base: Path, allowed: Path) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise PrivilegeSeparationError("effective YAML contains an invalid default rule path")
    path = Path(raw)
    path = path if path.is_absolute() else Path(base) / path
    _reject_symlink_components(path)
    resolved = path.resolve()
    if _protected(resolved) or not resolved.is_relative_to(allowed) or not resolved.is_dir():
        raise PrivilegeSeparationError("effective YAML default rule path is unsafe")
    return resolved


def _as_reference_list(configuration: dict, key: str) -> tuple[object, ...]:
    raw = configuration.get(key, ())
    if isinstance(raw, str):
        return (raw,)
    if raw is None:
        return ()
    if isinstance(raw, (list, tuple)):
        return tuple(raw)
    raise PrivilegeSeparationError(f"effective YAML {key} must be a string or list")


def referenced_configuration_files(
    configuration: dict, config_path: Path, *, allowed_root: Path | None = None,
) -> tuple[Path, ...]:
    """Resolve supported external dependencies, including nested YAML includes."""
    config_path = Path(config_path).resolve()
    allowed = Path(allowed_root).resolve() if allowed_root is not None else config_path.parent
    result: list[Path] = []
    active: set[Path] = set()
    visited: set[Path] = set()

    def visit(document: object, document_path: Path) -> None:
        if not isinstance(document, dict):
            raise PrivilegeSeparationError("effective YAML is not an object")
        if document_path in active:
            raise PrivilegeSeparationError("effective YAML include cycle is unsafe")
        if document_path in visited:
            return
        active.add(document_path)
        try:
            for key in ("classification-file", "reference-config-file", "threshold-file"):
                if document.get(key):
                    reference = _resolve_reference(document[key], document_path.parent, allowed)
                    if reference not in result:
                        result.append(reference)

            includes = []
            for key in ("include", "includes"):
                includes.extend(_as_reference_list(document, key))
            for raw in includes:
                reference = _resolve_reference(raw, document_path.parent, allowed)
                if reference not in result:
                    result.append(reference)
                try:
                    nested = yaml.safe_load(reference.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, yaml.YAMLError) as exc:
                    raise PrivilegeSeparationError("nested YAML include is unreadable") from exc
                visit(nested, reference)

            rule_values = _as_reference_list(document, "rule-files")
            non_active_rules = [item for item in rule_values if item != "active.rules"]
            if non_active_rules:
                default_rule_path = _resolve_reference_directory(
                    document.get("default-rule-path", document_path.parent),
                    document_path.parent, allowed,
                )
                for raw in non_active_rules:
                    reference = _resolve_reference(raw, default_rule_path, allowed)
                    if reference not in result:
                        result.append(reference)
        finally:
            active.remove(document_path)
            visited.add(document_path)

    visit(configuration, config_path)
    return tuple(result)


def confine_configuration_references(
    configuration: dict, source_config: Path, *, attempt_root: Path, allowed_root: Path,
) -> dict:
    """Copy approved dependencies into the attempt and rewrite YAML references."""
    import copy

    source_config = Path(source_config).resolve()
    allowed_root = Path(allowed_root).resolve()
    attempt_root = Path(attempt_root).resolve()
    if _protected(attempt_root):
        raise PrivilegeSeparationError("attempt-local reference path is protected")
    mapping: dict[Path, Path] = {}
    yaml_rewritten: set[Path] = set()
    active: set[Path] = set()

    def destination_for(source: Path) -> Path:
        try:
            relative = source.relative_to(allowed_root)
        except ValueError as exc:
            raise PrivilegeSeparationError("effective YAML reference escapes the isolated root") from exc
        return attempt_root / "references" / relative

    def relative_to_destination(path: Path, destination_parent: Path) -> str:
        return os.path.relpath(path, destination_parent).replace(os.sep, "/")

    def copy_dependency(source: Path, *, yaml_required: bool) -> Path:
        if source in mapping:
            if yaml_required and source not in yaml_rewritten:
                raise PrivilegeSeparationError("dependency is used as both YAML and opaque data")
            return mapping[source]
        if source in active:
            raise PrivilegeSeparationError("effective YAML include cycle is unsafe")
        destination = destination_for(source)
        if destination.exists() or destination.is_symlink():
            raise PrivilegeSeparationError("attempt-local reference would overwrite an artifact")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        active.add(source)
        try:
            if yaml_required:
                try:
                    document = yaml.safe_load(source.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, yaml.YAMLError) as exc:
                    raise PrivilegeSeparationError("nested YAML include is unreadable") from exc
                rewritten = rewrite_document(document, source, destination)
                with destination.open("x", encoding="utf-8") as output:
                    yaml.safe_dump(rewritten, output, sort_keys=False)
                yaml_rewritten.add(source)
            else:
                with source.open("rb") as input_file, destination.open("xb") as output_file:
                    shutil.copyfileobj(input_file, output_file)
        finally:
            active.remove(source)
        mapping[source] = destination
        return destination

    def rewrite_value(value: object, base: Path, destination_parent: Path, *, yaml_required=False) -> str:
        source = _resolve_reference(value, base, allowed_root)
        destination = copy_dependency(source, yaml_required=yaml_required)
        return relative_to_destination(destination, destination_parent)

    def rewrite_document(document: object, source: Path, destination: Path) -> dict:
        if not isinstance(document, dict):
            raise PrivilegeSeparationError("nested YAML include is not an object")
        rewritten = copy.deepcopy(document)
        for key in ("classification-file", "reference-config-file", "threshold-file"):
            if rewritten.get(key):
                rewritten[key] = rewrite_value(
                    rewritten[key], source.parent, destination.parent,
                )
        for key in ("include", "includes"):
            raw = rewritten.get(key)
            if isinstance(raw, str):
                rewritten[key] = rewrite_value(
                    raw, source.parent, destination.parent, yaml_required=True,
                )
            elif isinstance(raw, list):
                rewritten[key] = [
                    rewrite_value(item, source.parent, destination.parent, yaml_required=True)
                    for item in raw
                ]
            elif raw is not None:
                raise PrivilegeSeparationError(f"effective YAML {key} must be a string or list")

        raw_rules = rewritten.get("rule-files")
        if raw_rules is not None:
            rule_values = list(_as_reference_list(document, "rule-files"))
            non_active_rules = [item for item in rule_values if item != "active.rules"]
            if non_active_rules:
                default_rule_path = _resolve_reference_directory(
                    document.get("default-rule-path", source.parent),
                    source.parent, allowed_root,
                )
                destination_default = attempt_root / "references" / default_rule_path.relative_to(allowed_root)
                destination_default.mkdir(mode=0o700, parents=True, exist_ok=True)
                for index, item in enumerate(rule_values):
                    if item != "active.rules":
                        rule_values[index] = rewrite_value(
                            item, default_rule_path, destination_default,
                        )
                rewritten["default-rule-path"] = relative_to_destination(
                    destination_default, destination.parent,
                )
            rewritten["rule-files"] = rule_values[0] if isinstance(raw_rules, str) else rule_values
        return rewritten

    active.add(source_config)
    try:
        confined = rewrite_document(configuration, source_config, attempt_root / "suricata.yaml")
    finally:
        active.remove(source_config)
    return confined


_STATUS_VALUE = re.compile(r"^(Uid|Gid|Groups|State):\s*(.*)$")


def parse_proc_status(status_text: str) -> ProcIdentity:
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
    if len(uids) != 4 or len(gids) != 4 or not groups or values.get("State", "").startswith("Z"):
        raise PrivilegeSeparationError("Suricata process identity fields are incomplete or unsafe")
    return ProcIdentity(uids, gids, groups, values["State"])


def verify_proc_identity_text(status_text: str) -> ProcIdentity:
    identity = parse_proc_status(status_text)
    if not identity.is_expected():
        raise PrivilegeSeparationError("Suricata process identity or supplementary root group is unsafe")
    return identity


def read_process_identity(pid: int, *, proc_root: Path = Path("/proc")) -> ProcIdentity:
    if pid <= 0:
        raise PrivilegeSeparationError("invalid Suricata PID")
    try:
        status_text = (Path(proc_root) / str(pid) / "status").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PrivilegeSeparationError("Suricata /proc status is unavailable") from exc
    identity = parse_proc_status(status_text)
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError) as exc:
        raise PrivilegeSeparationError("Suricata process is not alive") from exc
    return identity


def verify_process_identity(
    pid: int, *, proc_root: Path = Path("/proc"), expected_uid: int = SERVICE_UID,
    expected_gid: int = SERVICE_GID,
) -> ProcIdentity:
    if pid <= 0:
        raise PrivilegeSeparationError("invalid Suricata PID")
    identity = read_process_identity(pid, proc_root=proc_root)
    if not identity.is_expected(expected_uid, expected_gid):
        raise PrivilegeSeparationError("Suricata process identity mismatch")
    return identity


def verify_attempt_socket_path(path: Path, attempt_root: Path) -> None:
    path = Path(path)
    root = Path(attempt_root).resolve()
    if path.is_symlink() or path.resolve().parent != (root / "runtime").resolve():
        raise PrivilegeSeparationError("Suricata control socket is outside the expected attempt")
    if path.exists() and not stat.S_ISSOCK(path.stat().st_mode):
        raise PrivilegeSeparationError("Suricata control path is not a UNIX socket")

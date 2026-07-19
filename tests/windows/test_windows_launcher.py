"""GREEN native-Windows guard for the permanent launcher contract.

The release contains two executables:

* ``codebase-memory-mcp.exe`` is the small permanent launcher.
* ``codebase-memory-mcp.payload.exe`` is the portable CBM payload.

Only ``install`` turns that pair into a managed installation.  A managed
launcher resolves its payload from a strict, fixed-size current-v1 record
relative to the launcher's own directory.  Portable package-manager payloads
remain useful for ordinary MCP/CLI commands, but must refuse self-update and
self-uninstall before they disturb an active daemon generation.

This guard deliberately crosses real CreateProcess/stdio/filesystem boundaries
on native Windows.  It also kills the launcher abruptly and inspects the
process tree, because a waiting launcher must own its payload child strongly
enough that killing the launcher cannot leave an orphaned MCP client.

Exit code: 0 == contract honored, 1 == regression, 2 == precondition failure.

Usage:
    python test_windows_launcher.py \
        <launcher.exe> <payload.exe> <abi-mismatch-launcher.exe>
"""

import ctypes
from ctypes import wintypes
import hashlib
import os
import pathlib
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

if os.name == "nt":
    import winreg

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_stdio import McpError, McpServer  # noqa: E402


CURRENT_MAGIC = b"CBMCUR1\0"
CURRENT_RECORD_SIZE = 128
CURRENT_FORMAT_OFFSET = 8
CURRENT_SIZE_OFFSET = 12
CURRENT_ABI_MIN_OFFSET = 16
CURRENT_ABI_MAX_OFFSET = 20
CURRENT_PAYLOAD_SIZE_OFFSET = 24
CURRENT_SHA256_OFFSET = 32
CURRENT_SHA256_SIZE = 64
CURRENT_RESERVED_OFFSET = 96

DESCRIPTOR_MAGIC = b"CBMWRD1\0"
DESCRIPTOR_RECORD_SIZE = 128
DESCRIPTOR_FORMAT_OFFSET = 8
DESCRIPTOR_SIZE_OFFSET = 12
DESCRIPTOR_LAUNCHER_ABI_OFFSET = 16
DESCRIPTOR_PAYLOAD_ABI_MIN_OFFSET = 20
DESCRIPTOR_PAYLOAD_ABI_MAX_OFFSET = 24
DESCRIPTOR_FLAGS_OFFSET = 28
DESCRIPTOR_PAYLOAD_SIZE_OFFSET = 32
DESCRIPTOR_SHA256_OFFSET = 40
DESCRIPTOR_RESERVED_OFFSET = 104

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102


class GuardFailure(Exception):
    pass


def sha256_file(path):
    """SHA-256 hex digest of a file's contents (payload/launcher digest checks)."""
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def require(condition, message):
    if not condition:
        raise GuardFailure(message)


def output_text(result):
    return ((result.stdout or b"") + b"\n" + (result.stderr or b"")).decode(
        "utf-8", "replace"
    )


def run(command, env, timeout=30):
    try:
        return subprocess.run(
            [str(part) for part in command],
            input=b"",
            capture_output=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise GuardFailure(
            "command exceeded %ss: %s" % (timeout, " ".join(map(str, command)))
        ) from exc


def isolated_environment(work):
    home = work / "home"
    cache = work / "cache"
    home.mkdir(parents=True)
    cache.mkdir(parents=True)
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "APPDATA": str(home / "AppData" / "Roaming"),
            "LOCALAPPDATA": str(home / "AppData" / "Local"),
            "CBM_CACHE_DIR": str(cache),
            "PYTHONUTF8": "1",
        }
    )
    return env, cache


def copy_portable_pair(source_launcher, source_payload, directory):
    directory.mkdir(parents=True, exist_ok=True)
    launcher = directory / "codebase-memory-mcp.exe"
    payload = directory / "codebase-memory-mcp.payload.exe"
    shutil.copy2(source_launcher, launcher)
    shutil.copy2(source_payload, payload)
    return launcher, payload


def copy_portable_payload(source_payload, directory):
    directory.mkdir(parents=True, exist_ok=True)
    payload = directory / "codebase-memory-mcp.payload.exe"
    shutil.copy2(source_payload, payload)
    return payload


def path_registry_snapshot():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, kind = winreg.QueryValueEx(key, "Path")
            return True, value, kind
    except FileNotFoundError:
        return False, None, None


def path_registry_restore(snapshot):
    existed, value, kind = snapshot
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
        if existed:
            winreg.SetValueEx(key, "Path", 0, kind, value)
        else:
            try:
                winreg.DeleteValue(key, "Path")
            except FileNotFoundError:
                pass


def find_and_validate_current(managed_dir):
    matches = []
    for candidate in (managed_dir / ".cbm").rglob("*"):
        if not candidate.is_file():
            continue
        try:
            data = candidate.read_bytes()
        except OSError:
            continue
        if len(data) == CURRENT_RECORD_SIZE and data.startswith(CURRENT_MAGIC):
            matches.append((candidate, data))
    require(
        len(matches) == 1,
        "managed layout must contain exactly one 128-byte CBMCUR1 current record; got %d"
        % len(matches),
    )
    current, data = matches[0]
    version = struct.unpack_from("<I", data, CURRENT_FORMAT_OFFSET)[0]
    size = struct.unpack_from("<I", data, CURRENT_SIZE_OFFSET)[0]
    abi_min = struct.unpack_from("<I", data, CURRENT_ABI_MIN_OFFSET)[0]
    abi_max = struct.unpack_from("<I", data, CURRENT_ABI_MAX_OFFSET)[0]
    payload_size = struct.unpack_from("<Q", data, CURRENT_PAYLOAD_SIZE_OFFSET)[0]
    try:
        digest = data[
            CURRENT_SHA256_OFFSET : CURRENT_SHA256_OFFSET + CURRENT_SHA256_SIZE
        ].decode("ascii")
    except UnicodeDecodeError as exc:
        raise GuardFailure("current-v1 SHA-256 is not ASCII") from exc

    require(version == 1, "current record is not current-v1")
    require(size == CURRENT_RECORD_SIZE, "current-v1 record_size is not 128")
    require(abi_min > 0 and abi_min <= abi_max, "current-v1 ABI range is invalid")
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "current-v1 digest is not lowercase SHA-256")
    require(
        data[CURRENT_RESERVED_OFFSET:] == bytes(CURRENT_RECORD_SIZE - CURRENT_RESERVED_OFFSET),
        "current-v1 reserved bytes must be zero",
    )

    payload = (
        managed_dir
        / ".cbm"
        / "generations"
        / digest
        / "codebase-memory-mcp.payload.exe"
    )
    require(payload.is_file(), "current-v1 generation payload is missing: %s" % payload)
    require(payload.stat().st_size == payload_size, "current-v1 payload size does not match")
    observed = hashlib.sha256(payload.read_bytes()).hexdigest()
    require(observed == digest, "installed generation name/digest does not match payload bytes")
    return current, data, payload


def parse_release_descriptor(data):
    require(len(data) == DESCRIPTOR_RECORD_SIZE, "release descriptor size is not 128")
    require(data[:8] == DESCRIPTOR_MAGIC, "release descriptor magic is invalid")
    require(
        struct.unpack_from("<I", data, DESCRIPTOR_FORMAT_OFFSET)[0] == 1,
        "release descriptor format is not v1",
    )
    require(
        struct.unpack_from("<I", data, DESCRIPTOR_SIZE_OFFSET)[0]
        == DESCRIPTOR_RECORD_SIZE,
        "release descriptor record_size is invalid",
    )
    launcher_abi = struct.unpack_from("<I", data, DESCRIPTOR_LAUNCHER_ABI_OFFSET)[0]
    payload_min = struct.unpack_from("<I", data, DESCRIPTOR_PAYLOAD_ABI_MIN_OFFSET)[0]
    payload_max = struct.unpack_from("<I", data, DESCRIPTOR_PAYLOAD_ABI_MAX_OFFSET)[0]
    flags = struct.unpack_from("<I", data, DESCRIPTOR_FLAGS_OFFSET)[0]
    payload_size = struct.unpack_from("<Q", data, DESCRIPTOR_PAYLOAD_SIZE_OFFSET)[0]
    digest = data[DESCRIPTOR_SHA256_OFFSET:DESCRIPTOR_RESERVED_OFFSET].decode("ascii")
    require(flags == 0, "release descriptor flags are nonzero")
    require(
        payload_min > 0 and payload_min <= launcher_abi <= payload_max,
        "release descriptor launcher/payload ABI range is incompatible",
    )
    require(payload_size > 0, "release descriptor payload size is zero")
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "release descriptor digest is invalid")
    require(
        data[DESCRIPTOR_RESERVED_OFFSET:] == bytes(
            DESCRIPTOR_RECORD_SIZE - DESCRIPTOR_RESERVED_OFFSET
        ),
        "release descriptor reserved bytes are nonzero",
    )
    return launcher_abi, payload_min, payload_max, payload_size, digest


def assert_release_descriptor(source_launcher, source_payload, env, cache):
    cache_before = sorted(str(path.relative_to(cache)) for path in cache.rglob("*"))
    result = run(
        [source_launcher, "__cbm_windows_release_descriptor_v1"], env, timeout=30
    )
    require(
        result.returncode == 0,
        "release descriptor probe failed: %s" % output_text(result)[-800:],
    )
    _, _, _, payload_size, digest = parse_release_descriptor(result.stdout)
    require(payload_size == source_payload.stat().st_size, "descriptor payload size mismatch")
    require(digest == sha256_file(source_payload), "descriptor payload digest mismatch")
    cache_after = sorted(str(path.relative_to(cache)) for path in cache.rglob("*"))
    require(cache_after == cache_before, "release descriptor probe touched cache/daemon state")
    print("PASS: release pair self-described ABI and payload identity without side effects")


def assert_portable_mutations_refuse(source_payload, env, cache, work):
    session_payload = copy_portable_payload(source_payload, work / "portable-session")
    with McpServer(str(session_payload), cache_dir=str(cache), extra_env=env) as server:
        server.initialize(timeout=30)
        require(server.tools_list(timeout=30), "portable MCP control session has no tools")

        for action, options in (
            ("update", ["--yes", "--standard"]),
            ("uninstall", ["--yes"]),
        ):
            command_payload = copy_portable_payload(
                source_payload, work / ("portable-" + action)
            )
            command_env = dict(env)
            # If the update guard regresses, keep its unintended network path
            # deterministic and fast.  A correct implementation refuses before
            # it consults this URL or asks the daemon to drain.
            command_env["CBM_DOWNLOAD_URL"] = "https://127.0.0.1:1"
            started = time.monotonic()
            result = run([command_payload, action] + options, command_env, timeout=10)
            elapsed = time.monotonic() - started
            diagnostic = output_text(result).lower()
            require(result.returncode != 0, "portable %s unexpectedly succeeded" % action)
            require(elapsed < 8.0, "portable %s did not fail early" % action)
            require(
                "install" in diagnostic
                and any(
                    word in diagnostic
                    for word in ("package manager", "managed", "launcher")
                ),
                "portable %s did not explain package-manager/managed-install recovery"
                % action,
            )
            # The same already-open stdio session must still own the same live
            # daemon connection.  A stop-and-transparent-restart is not enough:
            # the existing pipe itself has to remain usable.
            require(
                server.tools_list(timeout=10),
                "portable %s drained the active MCP/daemon session before refusing"
                % action,
            )
            print("PASS: portable %s refused early without draining the session" % action)


def assert_untrusted_ancestor_acl_rejected(
    source_launcher, source_payload, env, work
):
    unsafe_ancestor = work / "unsafe cross-account ACL ancestor"
    launcher, _ = copy_portable_pair(
        source_launcher, source_payload, unsafe_ancestor / "bundle"
    )
    require(
        run([launcher, "--version"], env).returncode == 0,
        "portable launcher ACL control failed before the unsafe ACE was added",
    )
    extended_launcher = "\\\\?\\" + str(launcher.resolve())
    extended_result = run([extended_launcher, "--version"], env)
    require(
        extended_result.returncode == 0,
        "launcher rejected its documented extended DOS module path: %s"
        % output_text(extended_result)[-600:],
    )

    grant = run(
        ["icacls", unsafe_ancestor, "/grant", "*S-1-1-0:(M)"], env
    )
    require(
        grant.returncode == 0,
        "could not install native Everyone-modify ancestor fixture: %s"
        % output_text(grant)[-600:],
    )
    try:
        for candidate, spelling in (
            (launcher, "normal"),
            (extended_launcher, "extended DOS"),
        ):
            result = run([candidate, "--version"], env)
            diagnostic = output_text(result).lower()
            require(
                result.returncode != 0,
                "%s launcher path accepted an ancestor granting cross-account modify access"
                % spelling,
            )
            require(
                any(
                    word in diagnostic
                    for word in (
                        "unsafe",
                        "security",
                        "ownership",
                        "access",
                        "resolve",
                    )
                ),
                "%s launcher path unsafe-ancestor refusal was not explicit"
                % spelling,
            )
    finally:
        remove = run(
            ["icacls", unsafe_ancestor, "/remove:g", "*S-1-1-0"], env
        )
        require(
            remove.returncode == 0,
            "could not remove native Everyone-modify ancestor fixture",
        )
    for candidate, spelling in (
        (launcher, "normal"),
        (extended_launcher, "extended DOS"),
    ):
        require(
            run([candidate, "--version"], env).returncode == 0,
            "%s launcher path did not recover after unsafe ancestor ACE removal"
            % spelling,
        )
    print("PASS: launcher rejected an untrusted mutation ACE on an ancestor")


def assert_add_only_ancestor_acl_allowed(source_launcher, source_payload, env, work):
    ancestor = work / "cross-account add-only ancestor"
    launcher, portable_payload = copy_portable_pair(
        source_launcher, source_payload, ancestor / "bundle"
    )
    grant = run(["icacls", ancestor, "/grant", "*S-1-1-0:(AD)"], env)
    require(
        grant.returncode == 0,
        "could not install native Everyone-add-subdirectory ancestor fixture: %s"
        % output_text(grant)[-600:],
    )
    try:
        for candidate, spelling in (
            (launcher, "normal"),
            ("\\\\?\\" + str(launcher.resolve()), "extended DOS"),
        ):
            result = run([candidate, "--version"], env)
            require(
                result.returncode == 0,
                "%s launcher path treated sibling creation as replacement access: %s"
                % (spelling, output_text(result)[-600:]),
            )

        managed_dir = ancestor / "managed install under add-only ancestor"
        install = run(
            [
                portable_payload,
                "install",
                "--yes",
                "--force",
                "--skip-config",
                "--dir",
                managed_dir,
            ],
            env,
            timeout=60,
        )
        require(
            install.returncode == 0,
            "managed install rejected a standard add-subdirectory-only ancestor: %s"
            % output_text(install)[-800:],
        )
        managed_launcher = managed_dir / "codebase-memory-mcp.exe"
        require(managed_launcher.is_file(), "add-only managed install produced no launcher")
        uninstall = run([managed_launcher, "uninstall", "--yes"], env, timeout=60)
        require(
            uninstall.returncode == 0,
            "add-only managed install could not be uninstalled: %s"
            % output_text(uninstall)[-800:],
        )
    finally:
        remove = run(["icacls", ancestor, "/remove:g", "*S-1-1-0"], env)
        require(
            remove.returncode == 0,
            "could not remove native Everyone-add-subdirectory ancestor fixture",
        )
    print(
        "PASS: launcher and managed install allowed add-only sibling creation "
        "without weakening path integrity"
    )


def assert_targeted_ancestor_acl_rejected(path, launcher, right, description, env):
    grant = run(["icacls", path, "/grant", "*S-1-1-0:(%s)" % right], env)
    require(
        grant.returncode == 0,
        "could not install native Everyone-%s fixture: %s"
        % (description, output_text(grant)[-600:]),
    )
    try:
        for candidate, spelling in (
            (launcher, "normal"),
            ("\\\\?\\" + str(launcher.resolve()), "extended DOS"),
        ):
            result = run([candidate, "--version"], env)
            require(
                result.returncode != 0,
                "%s launcher accepted cross-account %s"
                % (spelling, description),
            )
    finally:
        remove = run(["icacls", path, "/remove:g", "*S-1-1-0"], env)
        require(
            remove.returncode == 0,
            "could not remove native Everyone-%s fixture" % description,
        )
    require(
        run([launcher, "--version"], env).returncode == 0,
        "launcher did not recover after the %s ACE was removed" % description,
    )


def assert_file_add_and_executable_parent_acl_rejected(
    source_launcher, source_payload, env, work
):
    file_add_ancestor = work / "cross-account file-add ancestor"
    launcher, _ = copy_portable_pair(
        source_launcher, source_payload, file_add_ancestor / "bundle"
    )
    assert_targeted_ancestor_acl_rejected(
        file_add_ancestor, launcher, "WD", "file creation on an intermediate ancestor", env
    )

    executable_parent = work / "cross-account executable parent"
    launcher, _ = copy_portable_pair(source_launcher, source_payload, executable_parent)
    assert_targeted_ancestor_acl_rejected(
        executable_parent,
        launcher,
        "AD",
        "subdirectory creation beside the executable",
        env,
    )
    print("PASS: launcher kept file-add and executable-parent ACL boundaries strict")


def process_entries():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise GuardFailure("CreateToolhelp32Snapshot failed")
    entries = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            entries.append(
                (int(entry.th32ProcessID), int(entry.th32ParentProcessID), entry.szExeFile)
            )
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return entries


def process_is_alive(pid):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        return False
    try:
        status = kernel32.WaitForSingleObject(handle, 0)
        return status == WAIT_TIMEOUT
    finally:
        kernel32.CloseHandle(handle)


def wait_for_payload_child(launcher_pid, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        children = [
            (pid, name)
            for pid, parent, name in process_entries()
            if parent == launcher_pid
            and name.lower().endswith("codebase-memory-mcp.payload.exe")
        ]
        if len(children) == 1:
            return children[0][0]
        if len(children) > 1:
            raise GuardFailure("launcher spawned more than one direct payload child")
        time.sleep(0.05)
    raise GuardFailure("launcher did not create its direct payload child")


def wait_for_process_exit(pid, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_is_alive(pid):
            return True
        time.sleep(0.05)
    return not process_is_alive(pid)


def descendant_pids(root_pid):
    entries = process_entries()
    descendants = set()
    frontier = {root_pid}
    while frontier:
        next_frontier = {
            pid
            for pid, parent, _ in entries
            if parent in frontier and pid not in descendants
        }
        descendants.update(next_frontier)
        frontier = next_frontier
    return descendants


def assert_launcher_death_contains_payload(launcher, env, cache):
    server = McpServer(str(launcher), cache_dir=str(cache), extra_env=env)
    try:
        server.start()
        server.initialize(timeout=30)
        child_pid = wait_for_payload_child(server.proc.pid)
        require(process_is_alive(child_pid), "payload child exited before crash probe")
        server.proc.kill()
        server.proc.wait(timeout=10)
        require(
            wait_for_process_exit(child_pid, timeout=10),
            "killing the permanent launcher orphaned payload pid %d" % child_pid,
        )
        print("PASS: abrupt launcher death contained its payload child")
    finally:
        server.close()


def assert_immediate_parent_death_contains_launcher_tree(launcher, env, work):
    pid_file = work / "launcher-parent-probe.pid"
    wrapper = subprocess.Popen(
        [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--launcher-parent-probe",
            str(launcher),
            str(pid_file),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not pid_file.exists():
            if wrapper.poll() is not None:
                raise GuardFailure("parent-probe wrapper exited before publishing launcher PID")
            time.sleep(0.05)
        require(pid_file.exists(), "parent-probe wrapper did not publish launcher PID")
        launcher_pid = int(pid_file.read_text(encoding="ascii").strip())
        payload_pid = wait_for_payload_child(launcher_pid, timeout=10)
        tracked = {launcher_pid, payload_pid} | descendant_pids(launcher_pid)
        require(process_is_alive(launcher_pid), "launcher exited before parent-death probe")
        require(process_is_alive(payload_pid), "payload exited before parent-death probe")

        # Kill only the wrapper. The test process intentionally keeps the
        # wrapper stdin pipe open, so MCP EOF cannot explain child teardown.
        wrapper.kill()
        wrapper.wait(timeout=10)
        require(
            wait_for_process_exit(launcher_pid, timeout=10),
            "killing only the wrapper left launcher pid %d alive" % launcher_pid,
        )
        survivors = [pid for pid in tracked if process_is_alive(pid)]
        descendant_deadline = time.monotonic() + 10
        while survivors and time.monotonic() < descendant_deadline:
            time.sleep(0.05)
            survivors = [pid for pid in survivors if process_is_alive(pid)]
        require(not survivors, "wrapper death left launcher descendants alive: %s" % survivors)
        print("PASS: immediate parent death terminated launcher and payload session tree")
    finally:
        if wrapper.poll() is None:
            wrapper.kill()
            wrapper.wait(timeout=10)
        if wrapper.stdin:
            wrapper.stdin.close()


def assert_launcher_relay(launcher, payload, env, cache):
    direct_version = run([payload, "--version"], env)
    launched_version = run([launcher, "--version"], env)
    require(direct_version.returncode == 0, "managed payload --version failed")
    require(
        launched_version.returncode == direct_version.returncode,
        "launcher did not propagate the payload's success exit status exactly",
    )
    require(
        launched_version.stdout == direct_version.stdout
        and launched_version.stderr == direct_version.stderr,
        "launcher did not relay --version stdout/stderr byte-for-byte",
    )

    # A missing CLI tool has a stable non-zero product exit.  Compare it with
    # the same generation payload rather than baking the numeric code into the
    # launcher contract.
    direct_error = run([payload, "cli"], env)
    launched_error = run([launcher, "cli"], env)
    require(direct_error.returncode != 0, "CLI error control unexpectedly succeeded")
    require(
        launched_error.returncode == direct_error.returncode,
        "launcher changed the payload's non-zero exit status",
    )
    require(
        launched_error.stdout == direct_error.stdout
        and launched_error.stderr == direct_error.stderr,
        "launcher did not relay failing CLI stdout/stderr byte-for-byte",
    )

    with McpServer(str(launcher), cache_dir=str(cache), extra_env=env) as server:
        init = server.initialize(timeout=30)
        require("result" in init, "launcher did not relay MCP initialize response")
        require(server.tools_list(timeout=30), "launcher did not relay MCP tools/list")
    print("PASS: launcher relayed MCP stdio and exact child exit/status streams")


def assert_current_fail_closed(launcher, current, original, env):
    incompatible = bytearray(original)
    struct.pack_into("<II", incompatible, CURRENT_ABI_MIN_OFFSET, 0xFFFFFFFF, 0xFFFFFFFF)
    current.write_bytes(incompatible)
    result = run([launcher, "--version"], env)
    diagnostic = output_text(result).lower()
    require(result.returncode != 0, "launcher accepted an incompatible current-v1 ABI")
    require("abi" in diagnostic or "incompatible" in diagnostic, "ABI refusal was not explicit")

    corrupt = bytearray(original)
    corrupt[: len(CURRENT_MAGIC)] = b"\0" * len(CURRENT_MAGIC)
    current.write_bytes(corrupt)
    result = run([launcher, "--version"], env)
    diagnostic = output_text(result).lower()
    require(result.returncode != 0, "launcher accepted a corrupted current record")
    require(
        any(word in diagnostic for word in ("current", "corrupt", "invalid", "state")),
        "corrupted-current failure was not explicit",
    )
    current.write_bytes(original)
    require(run([launcher, "--version"], env).returncode == 0, "restored current-v1 stopped working")
    print("PASS: current-v1 compatibility succeeded and corrupt/incompatible state failed hard")


def assert_managed_update(
    source_launcher, source_payload, launcher, managed_dir, env, work
):
    release = work / "release"
    release.mkdir()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    asset_name = "codebase-memory-mcp-windows-%s.zip" % arch
    asset = release / asset_name
    with zipfile.ZipFile(asset, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.write(source_launcher, "codebase-memory-mcp.exe")
        archive.write(source_payload, "codebase-memory-mcp.payload.exe")
        archive.writestr("LICENSE", "test license\n")
        archive.writestr("install.ps1", "# test installer\n")
        archive.writestr("THIRD_PARTY_NOTICES.md", "test notices\n")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (release / "checksums.txt").write_text(
        "%s  %s\n" % (digest, asset_name), encoding="ascii"
    )

    update_env = dict(env)
    update_env["CBM_DOWNLOAD_URL"] = release.resolve().as_uri()
    orphan_bytes = source_payload.read_bytes() + b"\0CBM generation prune fixture\n"
    orphan_digest = hashlib.sha256(orphan_bytes).hexdigest()
    orphan_directory = managed_dir / ".cbm" / "generations" / orphan_digest
    orphan_directory.mkdir()
    (orphan_directory / "codebase-memory-mcp.payload.exe").write_bytes(orphan_bytes)
    result = run(
        [launcher, "update", "--force", "--standard", "--yes"],
        update_env,
        timeout=90,
    )
    require(
        result.returncode == 0,
        "managed update failed: %s" % output_text(result)[-1200:],
    )
    require(launcher.is_file(), "managed update removed the canonical launcher")
    _, _, generation_payload = find_and_validate_current(managed_dir)
    require(
        run([launcher, "--version"], env).returncode == 0,
        "managed update returned with a non-runnable launcher/current pair",
    )
    require(
        run([generation_payload, "--version"], env).returncode == 0,
        "managed update returned with a non-runnable generation payload",
    )
    require(not orphan_directory.exists(), "successful update did not prune old generation")
    generation_directories = [
        path
        for path in (managed_dir / ".cbm" / "generations").iterdir()
        if path.is_dir()
    ]
    require(
        len(generation_directories) == 1
        and generation_directories[0].name == generation_payload.parent.name,
        "successful update did not leave exactly the current generation",
    )
    print("PASS: managed update committed a runnable pair and pruned non-current generations")


def assert_managed_update_rejects_unrunnable_launcher_before_drain(
    source_payload, launcher, managed_dir, env, cache, work
):
    release = work / "release-unrunnable-launcher"
    release.mkdir()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    asset_name = "codebase-memory-mcp-windows-%s.zip" % arch
    asset = release / asset_name
    with zipfile.ZipFile(asset, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("codebase-memory-mcp.exe", b"MZ-not-a-runnable-launcher")
        archive.write(source_payload, "codebase-memory-mcp.payload.exe")
        archive.writestr("LICENSE", "test license\n")
        archive.writestr("install.ps1", "# test installer\n")
        archive.writestr("THIRD_PARTY_NOTICES.md", "test notices\n")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (release / "checksums.txt").write_text(
        "%s  %s\n" % (digest, asset_name), encoding="ascii"
    )
    update_env = dict(env)
    update_env["CBM_DOWNLOAD_URL"] = release.resolve().as_uri()
    current, current_before, _ = find_and_validate_current(managed_dir)
    launcher_before = sha256_file(launcher)

    with McpServer(str(launcher), cache_dir=str(cache), extra_env=env) as server:
        server.initialize(timeout=30)
        result = run(
            [launcher, "update", "--force", "--standard", "--yes"],
            update_env,
            timeout=60,
        )
        diagnostic = output_text(result).lower()
        require(result.returncode != 0, "unrunnable launcher update succeeded")
        require(
            any(word in diagnostic for word in ("launcher", "candidate", "runnable", "capability")),
            "unrunnable launcher rejection was not explicit",
        )
        require(
            server.tools_list(timeout=10),
            "unrunnable launcher candidate drained the active managed session",
        )

    require(sha256_file(launcher) == launcher_before, "failed update replaced the launcher")
    require(current.read_bytes() == current_before, "failed update changed current-v1")
    print("PASS: unrunnable update launcher failed before session drain")


def assert_managed_update_rejects_cross_abi_pair_before_drain(
    abi_mismatch_launcher, source_payload, launcher, managed_dir, env, cache, work
):
    release = work / "release-abi-mismatch"
    release.mkdir()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    asset_name = "codebase-memory-mcp-windows-%s.zip" % arch
    asset = release / asset_name
    with zipfile.ZipFile(asset, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.write(abi_mismatch_launcher, "codebase-memory-mcp.exe")
        archive.write(source_payload, "codebase-memory-mcp.payload.exe")
        archive.writestr("LICENSE", "test license\n")
        archive.writestr("install.ps1", "# test installer\n")
        archive.writestr("THIRD_PARTY_NOTICES.md", "test notices\n")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (release / "checksums.txt").write_text(
        "%s  %s\n" % (digest, asset_name), encoding="ascii"
    )
    update_env = dict(env)
    update_env["CBM_DOWNLOAD_URL"] = release.resolve().as_uri()
    current, current_before, _ = find_and_validate_current(managed_dir)
    launcher_before = sha256_file(launcher)
    generations_before = sorted(
        str(path.relative_to(managed_dir))
        for path in (managed_dir / ".cbm" / "generations").rglob("*")
    )

    with McpServer(str(launcher), cache_dir=str(cache), extra_env=env) as server:
        server.initialize(timeout=30)
        result = run(
            [launcher, "update", "--force", "--standard", "--yes"],
            update_env,
            timeout=60,
        )
        diagnostic = output_text(result).lower()
        require(result.returncode != 0, "cross-ABI launcher/payload update succeeded")
        require(
            any(word in diagnostic for word in ("abi", "descriptor", "bridge", "incompatible")),
            "cross-ABI update refusal did not explain compatibility failure",
        )
        require(
            server.tools_list(timeout=10),
            "cross-ABI candidate drained the active managed session",
        )

    generations_after = sorted(
        str(path.relative_to(managed_dir))
        for path in (managed_dir / ".cbm" / "generations").rglob("*")
    )
    require(sha256_file(launcher) == launcher_before, "cross-ABI update replaced launcher")
    require(current.read_bytes() == current_before, "cross-ABI update changed current-v1")
    require(generations_after == generations_before, "cross-ABI update published a generation")
    print("PASS: incompatible future launcher ABI failed hard before session drain")


def assert_failed_update_rolls_back_new_generation(
    source_launcher, source_payload, launcher, managed_dir, env, work
):
    release = work / "release-generation-rollback"
    release.mkdir()
    mutated_payload = release / "mutated.payload.exe"
    mutated_payload.write_bytes(
        source_payload.read_bytes() + b"\0CBM generation rollback fixture\n"
    )
    require(
        run([mutated_payload, "--version"], env).returncode == 0,
        "PE overlay payload fixture is not runnable",
    )
    mutated_digest = sha256_file(mutated_payload)
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    asset_name = "codebase-memory-mcp-windows-%s.zip" % arch
    asset = release / asset_name
    with zipfile.ZipFile(asset, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.write(source_launcher, "codebase-memory-mcp.exe")
        archive.write(mutated_payload, "codebase-memory-mcp.payload.exe")
        archive.writestr("LICENSE", "test license\n")
        archive.writestr("install.ps1", "# test installer\n")
        archive.writestr("THIRD_PARTY_NOTICES.md", "test notices\n")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (release / "checksums.txt").write_text(
        "%s  %s\n" % (digest, asset_name), encoding="ascii"
    )
    update_env = dict(env)
    update_env["CBM_DOWNLOAD_URL"] = release.resolve().as_uri()
    current, current_before, _ = find_and_validate_current(managed_dir)
    launcher_before = sha256_file(launcher)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    held_launcher = kernel32.CreateFileW(
        str(launcher), 0x80000000, 0x00000001, None, 3, 0x80, None
    )
    require(held_launcher != INVALID_HANDLE_VALUE, "could not lock canonical launcher fixture")
    try:
        result = run(
            [launcher, "update", "--force", "--standard", "--yes"],
            update_env,
            timeout=90,
        )
    finally:
        kernel32.CloseHandle(held_launcher)
    require(result.returncode != 0, "forced post-publication launcher failure succeeded")
    require(sha256_file(launcher) == launcher_before, "failed update changed launcher")
    require(current.read_bytes() == current_before, "failed update changed current-v1")
    require(
        not (managed_dir / ".cbm" / "generations" / mutated_digest).exists(),
        "failed update orphaned its newly published generation",
    )
    print("PASS: post-publication update failure rolled back its new generation")


def assert_managed_update_dry_run_skips_capability_probe(
    launcher, managed_dir, env
):
    dry_env = dict(env)
    dry_env["CBM_TEST_WINDOWS_LAUNCHER_CAPABILITY_PROBE"] = "fail"
    current, current_before, _ = find_and_validate_current(managed_dir)
    launcher_before = sha256_file(launcher)
    result = run(
        [launcher, "update", "--dry-run", "--force", "--standard", "--yes"],
        dry_env,
        timeout=30,
    )
    require(
        result.returncode == 0,
        "managed update dry-run invoked the forced-failing capability probe: %s"
        % output_text(result)[-800:],
    )
    require(sha256_file(launcher) == launcher_before, "update dry-run changed launcher")
    require(current.read_bytes() == current_before, "update dry-run changed current-v1")
    leftovers = [
        path
        for path in managed_dir.iterdir()
        if path.name.startswith(".cbm-launcher-probe-")
        or path.name == ".cbm-probe-path-check"
    ]
    require(not leftovers, "update dry-run left capability-probe artifacts: %s" % leftovers)
    print("PASS: managed update dry-run skipped mapped-image capability mutation")


def assert_capability_probe_fail_hard(
    source_launcher, source_payload, launcher, env, cache, work
):
    _, probe_payload = copy_portable_pair(
        source_launcher, source_payload, work / "portable-probe"
    )
    rejected_dir = work / "probe-rejected_日本語"
    rejected_env = dict(env)
    # Deterministic native fault injection for the exact-volume launcher
    # capability probe.  Production must treat this solely as a probe failure;
    # it must not bypass or weaken the real NTFS checks.
    rejected_env["CBM_TEST_WINDOWS_LAUNCHER_CAPABILITY_PROBE"] = "fail"

    with McpServer(str(launcher), cache_dir=str(cache), extra_env=env) as server:
        server.initialize(timeout=30)
        result = run(
            [
                probe_payload,
                "install",
                "--yes",
                "--force",
                "--skip-config",
                "--dir",
                rejected_dir,
            ],
            rejected_env,
            timeout=30,
        )
        diagnostic = output_text(result).lower()
        require(result.returncode != 0, "forced launcher capability-probe failure succeeded")
        require(
            any(word in diagnostic for word in ("capability", "ntfs", "atomic", "replace")),
            "launcher capability-probe failure was not explicit",
        )
        leftover_files = [p for p in rejected_dir.rglob("*") if p.is_file()]
        require(not leftover_files, "failed capability probe left managed-install files behind")
        require(
            server.tools_list(timeout=10),
            "capability-probe failure drained the already-active managed session",
        )
    print("PASS: unsupported launcher capability failed hard before session drain")


def assert_managed_uninstall(launcher, managed_dir, env):
    result = run([launcher, "uninstall", "--yes"], env, timeout=60)
    require(result.returncode == 0, "managed uninstall failed: %s" % output_text(result)[-800:])
    require(not launcher.exists(), "managed uninstall returned before launcher removal")
    state = managed_dir / ".cbm"
    leftovers = [p for p in state.rglob("*") if p.is_file()] if state.exists() else []
    require(not leftovers, "managed uninstall left generation/current files behind: %s" % leftovers)
    print("PASS: managed uninstall synchronously removed launcher and generation state")


def launcher_parent_probe_role():
    launcher = pathlib.Path(sys.argv[2]).resolve()
    pid_file = pathlib.Path(sys.argv[3]).resolve()
    child = subprocess.Popen(
        [str(launcher)],
        stdin=None,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=os.environ.copy(),
    )
    pid_file.write_text(str(child.pid), encoding="ascii")
    return child.wait()


def main():
    if os.name != "nt":
        print("PRECONDITION: native Windows is required")
        return 2
    if len(sys.argv) == 4 and sys.argv[1] == "--launcher-parent-probe":
        return launcher_parent_probe_role()
    if len(sys.argv) != 4:
        print(
            "usage: python test_windows_launcher.py "
            "<launcher.exe> <payload.exe> <abi-mismatch-launcher.exe>"
        )
        return 2

    source_launcher = pathlib.Path(sys.argv[1]).resolve()
    source_payload = pathlib.Path(sys.argv[2]).resolve()
    abi_mismatch_launcher = pathlib.Path(sys.argv[3]).resolve()
    if not source_launcher.is_file():
        print("PRECONDITION: launcher not found: %s" % source_launcher)
        return 2
    if not source_payload.is_file():
        print("PRECONDITION: payload not found: %s" % source_payload)
        return 2
    if not abi_mismatch_launcher.is_file():
        print("PRECONDITION: ABI mismatch launcher not found: %s" % abi_mismatch_launcher)
        return 2
    if source_launcher.samefile(source_payload):
        print("PRECONDITION: launcher and payload must be distinct executables")
        return 2

    work = pathlib.Path(tempfile.mkdtemp(prefix="cbm_win_launcher_"))
    path_snapshot = path_registry_snapshot()
    try:
        env, cache = isolated_environment(work)
        assert_release_descriptor(source_launcher, source_payload, env, cache)
        assert_portable_mutations_refuse(source_payload, env, cache, work)
        assert_add_only_ancestor_acl_allowed(
            source_launcher, source_payload, env, work
        )
        assert_file_add_and_executable_parent_acl_rejected(
            source_launcher, source_payload, env, work
        )
        assert_untrusted_ancestor_acl_rejected(
            source_launcher, source_payload, env, work
        )

        _, portable_payload = copy_portable_pair(
            source_launcher, source_payload, work / "portable-install"
        )
        managed_dir = work / "managed café_日本語 with spaces"
        # Reproduce the only durable partial state in a fresh launcher-first
        # publication: the canonical launcher rename completed, then the
        # process died before current-v1 was published. A retry must repair an
        # exact private candidate, while the native preflight still rejects an
        # unrelated conflicting launcher.
        managed_dir.mkdir(parents=True)
        interrupted_launcher = managed_dir / "codebase-memory-mcp.exe"
        shutil.copy2(abi_mismatch_launcher, interrupted_launcher)
        conflict = run(
            [
                portable_payload,
                "install",
                "--yes",
                "--force",
                "--skip-config",
                "--dir",
                managed_dir,
            ],
            env,
            timeout=30,
        )
        require(
            conflict.returncode != 0,
            "fresh install accepted an unrelated launcher-only conflict",
        )
        require(
            sha256_file(interrupted_launcher) == sha256_file(abi_mismatch_launcher),
            "rejected launcher-only conflict was modified",
        )
        shutil.copy2(source_launcher, interrupted_launcher)
        install = run(
            [
                portable_payload,
                "install",
                "--yes",
                "--force",
                "--skip-config",
                "--dir",
                managed_dir,
            ],
            env,
            timeout=60,
        )
        require(install.returncode == 0, "managed install failed: %s" % output_text(install)[-800:])

        launcher = managed_dir / "codebase-memory-mcp.exe"
        require(launcher.is_file(), "managed custom path has no canonical launcher")
        current, current_bytes, generation_payload = find_and_validate_current(managed_dir)
        print(
            "PASS: interrupted fresh install recovered into a strict current-v1 "
            "generation layout"
        )

        assert_launcher_relay(launcher, generation_payload, env, cache)
        assert_current_fail_closed(launcher, current, current_bytes, env)
        assert_managed_update_dry_run_skips_capability_probe(
            launcher, managed_dir, env
        )
        assert_managed_update_rejects_unrunnable_launcher_before_drain(
            source_payload, launcher, managed_dir, env, cache, work
        )
        assert_managed_update_rejects_cross_abi_pair_before_drain(
            abi_mismatch_launcher,
            source_payload,
            launcher,
            managed_dir,
            env,
            cache,
            work,
        )
        assert_failed_update_rolls_back_new_generation(
            source_launcher,
            source_payload,
            launcher,
            managed_dir,
            env,
            work,
        )
        assert_managed_update(
            source_launcher,
            source_payload,
            launcher,
            managed_dir,
            env,
            work,
        )
        assert_launcher_death_contains_payload(launcher, env, cache)
        assert_immediate_parent_death_contains_launcher_tree(
            launcher, env, work
        )
        assert_capability_probe_fail_hard(
            source_launcher, source_payload, launcher, env, cache, work
        )
        assert_managed_uninstall(launcher, managed_dir, env)
        print("\nGREEN: permanent Windows launcher contract honored.")
        return 0
    except (GuardFailure, McpError, OSError, subprocess.SubprocessError) as exc:
        print("\nRED: %s" % exc)
        return 1
    finally:
        try:
            path_registry_restore(path_snapshot)
        except OSError as exc:
            print("CLEANUP WARNING: could not restore HKCU Environment\\Path: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

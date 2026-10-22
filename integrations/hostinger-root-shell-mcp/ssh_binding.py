"""Read-only status of explicitly prepared per-target SSH identities.

Do not parse or return private key material, use host_keys_candidate as trust,
or infer that an authorized_keys copy proves live SSH authentication.
"""
import os
import stat
import asyncio
from pathlib import Path

BINDING_DIRECTORY = Path(os.environ.get("INFRA_SSH_BINDINGS_DIR", "/run/secrets/external-targets"))


def _regular_file(path: Path, private: bool = False) -> bool:
    try:
        info = path.lstat()
    except (OSError, ValueError):
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        return False
    if private and (stat.S_IMODE(info.st_mode) & 0o077):
        return False
    return True


def summarize_ssh_binding(target: dict) -> dict:
    """Non-secret health projection for an enrolled SSH target."""
    target_id = target["id"]
    if target_id == "hostinger-primary":
        return {
            "status": "managed_by_existing_root_shell",
            "authenticated": False,
            "data_access_verified": False,
        }
    directory = BINDING_DIRECTORY / target_id
    if directory.is_symlink() or not directory.is_dir():
        return {
            "status": "identity_directory_not_mounted",
            "authenticated": False,
            "data_access_verified": False,
        }

    private_ready = _regular_file(directory / "id_ed25519", private=True)
    public_ready = _regular_file(directory / "id_ed25519.pub")
    candidate = _regular_file(directory / "host_keys_candidate")
    pinned = _regular_file(directory / "known_hosts_verified")
    if not private_ready or not public_ready:
        status = "identity_incomplete_or_permissions_invalid"
    elif not pinned:
        status = "identity_prepared_host_key_not_verified"
    else:
        status = "identity_prepared_host_key_file_present"

    return {
        "status": status,
        "ssh_identity_present_mode_safe": private_ready,
        "public_identity_present": public_ready,
        "host_key_candidate_present": candidate,
        "verified_host_key_file_present": pinned,
        "authenticated": False,
        "data_access_verified": False,
    }


async def probe_authenticated_ssh(target_id: str) -> dict:
    """One bounded, non-mutating SSH auth proof for an enrolled target.

    The only remote command is a fixed printf sentinel. Never return SSH
    stdout/stderr, key material, or permit caller-controlled commands.
    """
    from providers import registered_target

    target = registered_target(target_id)
    if target["kind"] != "ssh" or target_id == "hostinger-primary":
        raise ValueError("target is not an external SSH account")
    if not target.get("username"):
        raise ValueError("target has no enrolled username")
    directory = BINDING_DIRECTORY / target_id
    readiness = summarize_ssh_binding(target)
    base = {
        "target_id": target_id,
        "port": target["port"] or 22,
        "authenticated": False,
        "data_access_verified": False,
        "mutation_performed": False,
    }
    if readiness["status"] != "identity_prepared_host_key_file_present":
        return {**base, "status": readiness["status"]}

    hostfile = directory / "known_hosts_verified"
    # Refuse an untrusted/symlinked file or a pin for the wrong enrolled host.
    if not _regular_file(hostfile, private=True):
        return {**base, "status": "verified_host_key_file_invalid"}
    try:
        pins = hostfile.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return {**base, "status": "verified_host_key_file_invalid"}
    required_host = f'[{target["host"]}]:{base["port"]}'
    valid_pins = [x.split() for x in pins if x.strip() and not x.lstrip().startswith("#")]
    if not any(len(v) >= 3 and required_host in v[0].split(",") for v in valid_pins):
        return {**base, "status": "target_host_key_pin_missing"}

    argv = [
        "ssh", "-F", "/dev/null", "-T",
        "-p", str(base["port"]),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UserKnownHostsFile=" + str(hostfile),
        "-o", "ConnectionAttempts=1",
        "-o", "ConnectTimeout=8",
        "-i", str(directory / "id_ed25519"),
        target["username"] + "@" + target["host"],
        "printf MAD4B_SSH_AUTH_OK",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=18)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {**base, "status": "connection_timeout"}
    except OSError:
        return {**base, "status": "ssh_client_unavailable"}

    if proc.returncode == 0 and stdout == b"MAD4B_SSH_AUTH_OK":
        return {**base, "status": "authenticated", "authenticated": True,
                "data_access_verified": True}
    error = stderr.decode("utf-8", "replace").lower()
    if "host key verification failed" in error or "remote host identification has changed" in error:
        category = "host_key_verification_failed"
    elif "permission denied" in error or "publickey" in error:
        category = "public_key_auth_denied"
    elif "connection refused" in error:
        category = "connection_refused"
    elif "timed out" in error:
        category = "connection_timeout"
    else:
        category = "authentication_or_remote_probe_failed"
    return {**base, "status": category}

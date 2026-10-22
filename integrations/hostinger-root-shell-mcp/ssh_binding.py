"""Read-only status of explicitly prepared per-target SSH identities.

Do not parse or return private key material, use host_keys_candidate as trust,
or infer that an authorized_keys copy proves live SSH authentication.
"""
import os
import stat
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

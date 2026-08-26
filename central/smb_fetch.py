"""Copy a Sentinel packet.db from an SMB/CIFS URL to a local cache."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlparse

import smbclient


class SmbError(Exception):
    """Raised when an SMB database cannot be fetched."""


def is_smb_path(value: str) -> bool:
    raw = (value or "").strip().lower()
    return raw.startswith("smb://") or raw.startswith("cifs://") or raw.startswith("\\\\")


def parse_smb_location(value: str) -> dict[str, str | int | None]:
    raw = (value or "").strip()
    if raw.startswith("\\\\"):
        parts = [p for p in raw.replace("\\", "/").split("/") if p]
        if len(parts) < 3:
            raise SmbError("UNC path must be \\\\host\\share\\file")
        host, share, rel = parts[0], parts[1], "/".join(parts[2:])
        return {"host": host, "port": 445, "share": share, "relpath": rel, "username": None, "password": None}

    parsed = urlparse(raw)
    if parsed.scheme not in {"smb", "cifs"}:
        raise SmbError(f"not an SMB URL: {value}")
    host = parsed.hostname
    if not host:
        raise SmbError("SMB URL is missing a host")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise SmbError("SMB URL must be smb://host/share/path/to/packet.db")
    return {
        "host": host,
        "port": parsed.port or 445,
        "share": parts[0],
        "relpath": "/".join(parts[1:]),
        "username": unquote(parsed.username) if parsed.username else None,
        "password": unquote(parsed.password) if parsed.password else None,
    }


def _unc(host: str, share: str, relpath: str) -> str:
    return r"\\" + host + "\\" + share + "\\" + relpath.replace("/", "\\")


def _connect(host: str, username: str | None, password: str | None, port: int) -> None:
    user = (username or "").strip() or "guest"
    kwargs = dict(
        username=user,
        password=password or "",
        port=int(port or 445),
        encrypt=False,
        auth_protocol="ntlm",
        connection_timeout=10,
    )
    # Authenticated Samba shares often require signing; guest sessions often forbid it.
    signing = False if user.lower() == "guest" else True
    try:
        smbclient.register_session(host, require_signing=signing, **kwargs)
    except Exception:
        smbclient.reset_connection_cache()
        smbclient.register_session(host, require_signing=not signing, **kwargs)


def _copy_file(unc: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with smbclient.open_file(unc, mode="rb", buffering=0) as src, tmp.open("wb") as out:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dest)


def fetch_smb_database(
    url: str,
    cache_dir: Path,
    *,
    username: str | None = None,
    password: str | None = None,
) -> Path:
    loc = parse_smb_location(url)
    host = str(loc["host"])
    share = str(loc["share"])
    relpath = str(loc["relpath"])
    user = username or loc["username"]
    pw = password if password is not None else loc["password"]
    unc = _unc(host, share, relpath)
    dest = cache_dir / Path(relpath).name
    cache_dir.mkdir(parents=True, exist_ok=True)

    try:
        smbclient.reset_connection_cache()
        _connect(host, user, pw, int(loc["port"] or 445))
        if not smbclient.path.isfile(unc):
            raise SmbError(f"SMB file not found: {url}")
        _copy_file(unc, dest)
        for sidecar in (relpath + "-wal", relpath + "-shm"):
            extra_unc = _unc(host, share, sidecar)
            extra_dest = cache_dir / Path(sidecar).name
            try:
                if smbclient.path.isfile(extra_unc):
                    _copy_file(extra_unc, extra_dest)
                elif extra_dest.exists():
                    extra_dest.unlink()
            except Exception:
                pass
    except SmbError:
        raise
    except Exception as exc:
        text = str(exc)
        if "ACCESS_DENIED" in text or "0xc0000022" in text:
            raise SmbError(
                f"SMB access denied for {url}. Enter the Samba username and password on the Clients page."
            ) from exc
        if "LOGON_FAILURE" in text or "0xc000006d" in text:
            raise SmbError(
                f"SMB login failed for {url}. Check the Samba username and password."
            ) from exc
        raise SmbError(f"could not read {url}: {exc}") from exc
    finally:
        try:
            smbclient.reset_connection_cache()
        except Exception:
            pass

    return dest

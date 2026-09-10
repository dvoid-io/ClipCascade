import os
import shutil
import ssl
from typing import Any, Dict, Optional, Union

from core.constants import MACOS, PLATFORM, get_program_files_directory

if PLATFORM == MACOS:
    import certifi

CA_BUNDLE_FILE_NAME = "cacert.pem"


def _macos_ca_bundle() -> str:
    """
    Path to a CA bundle that outlives the PyInstaller extraction directory.

    In the one-file bundle certifi.where() resolves under /var/folders/.../T/_MEI*, and
    macOS's daily dirhelper purge deletes files there that have not been accessed for
    three days, while the app is still running. Copy the bundle once into the app's
    data directory and use it from there; until the copy exists, use certifi's file.
    """
    src = certifi.where()
    dst = os.path.join(get_program_files_directory(), CA_BUNDLE_FILE_NAME)
    try:
        if os.path.isfile(src) and (
            not os.path.isfile(dst) or os.path.getsize(dst) != os.path.getsize(src)
        ):
            tmp = dst + ".tmp"
            shutil.copyfile(src, tmp)
            os.replace(tmp, dst)
    except OSError:
        pass
    return dst if os.path.isfile(dst) else src


def requests_verify_arg(config) -> Union[bool, str]:
    """Argument for requests' verify= when calling the user's server."""
    path = (config.data.get("ssl_ca_bundle") or "").strip()
    if not path:
        if PLATFORM == MACOS:
            return _macos_ca_bundle()
        return True
    if not os.path.isfile(path):
        raise FileNotFoundError(f"SSL CA bundle file not found: {path}")
    return path


def websocket_sslopt_for_config(config) -> Optional[Dict[str, Any]]:
    """sslopt for websocket_client run_forever; None uses the library/OS default."""
    path = (config.data.get("ssl_ca_bundle") or "").strip()
    if path:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"SSL CA bundle file not found: {path}")
        ctx = ssl.create_default_context(cafile=path)
        return {"context": ctx}
    if PLATFORM == MACOS:
        ctx = ssl.create_default_context(cafile=_macos_ca_bundle())
        return {"context": ctx}
    return None

"""Update notifications and self-update for the strix CLI.

Follows the pattern used by tools like gh, uv, and pip: a background,
rate-limited (once per 24h) check against the release source, a cached
result in ``~/.strix``, a non-intrusive notice with the upgrade command
for the detected install method, and a ``strix --update`` self-update
path for the standalone binary install.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.prompt import Prompt

from strix.telemetry._common import get_version


logger = logging.getLogger(__name__)

GITHUB_REPO = "usestrix/strix"
PYPI_PACKAGE = "strix-agent"
CHECK_INTERVAL_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT_SECONDS = 5

_CACHE_PATH = Path.home() / ".strix" / "update-check.json"

_background_thread: threading.Thread | None = None


def _is_disabled() -> bool:
    return bool(os.environ.get("STRIX_NO_UPDATE_CHECK")) or any(
        os.environ.get(key)
        for key in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "CIRCLECI")
    )


def is_binary_install() -> bool:
    return bool(getattr(sys, "frozen", False))


def get_install_method() -> str:
    if is_binary_install():
        return "binary"
    prefix = str(Path(sys.prefix)).replace("\\", "/")
    if "/pipx/" in prefix or prefix.endswith("/pipx"):
        return "pipx"
    if "/uv/tools/" in prefix:
        return "uv"
    return "pip"


def get_upgrade_command(method: str | None = None) -> str:
    method = method or get_install_method()
    commands = {
        "binary": "strix --update",
        "pipx": "pipx upgrade strix-agent",
        "uv": "uv tool upgrade strix-agent",
        "pip": "pip install --upgrade strix-agent",
    }
    return commands[method]


def _parse_version(value: str) -> tuple[int, ...] | None:
    parts = value.strip().lstrip("v").split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def _is_newer(latest: str, current: str) -> bool:
    latest_parts = _parse_version(latest)
    current_parts = _parse_version(current)
    if latest_parts is None or current_parts is None:
        return False
    return latest_parts > current_parts


def _fetch_latest_version() -> str | None:
    try:
        if is_binary_install():
            with requests.get(
                f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                timeout=REQUEST_TIMEOUT_SECONDS,
            ) as response:
                response.raise_for_status()
                tag = response.json().get("tag_name", "")
            return tag.lstrip("v") or None
        with requests.get(
            f"https://pypi.org/pypi/{PYPI_PACKAGE}/json",
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as response:
            response.raise_for_status()
            version = response.json().get("info", {}).get("version")
        return str(version) if version else None
    except Exception:  # noqa: BLE001
        logger.debug("update check failed", exc_info=True)
        return None


class ChecksumUnavailableError(RuntimeError):
    """Không lấy được checksum để xác minh artifact cập nhật.

    Vá 02/10/2026 (vuln-0014, CWE-494). Trước đây `_fetch_asset_digest()` trả
    `None` cho MỌI trường hợp (release không công bố digest, lỗi mạng, tên asset
    không khớp), và nhánh thiếu digest bị BỎ QUA — nghĩa là chỉ cần làm cho
    GitHub API không trả digest là đưa được binary lạ vào bước cài đặt.

    Nay: thiếu checksum ⇒ DỪNG cập nhật (fail-closed) và nêu rõ nguyên nhân.
    """


def _fetch_asset_digest(version: str, filename: str) -> str:
    """Trả sha256 (hex) của artifact. NÉM lỗi nếu không xác minh được.

    Phân biệt rõ ba trạng thái — cả ba đều dẫn tới DỪNG cập nhật, nhưng thông
    báo nêu đúng nguyên nhân để người dùng biết chuyện gì xảy ra:

    ==========================================  ==============================
    Trạng thái                                  Kết quả
    ==========================================  ==============================
    Lỗi mạng/HTTP khi tra cứu                   ChecksumUnavailableError
    Tên asset không có trong release            ChecksumUnavailableError
    Release thật sự không công bố `digest`      ChecksumUnavailableError
    Có digest sha256 hợp lệ                     trả về hex
    ==========================================  ==============================
    """
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/tags/v{version}"
    try:
        with requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            response.raise_for_status()
            assets = response.json().get("assets", [])
    except Exception as exc:  # noqa: BLE001
        raise ChecksumUnavailableError(
            f"không tra cứu được checksum của bản phát hành v{version} "
            f"(lỗi mạng/HTTP tới api.github.com): {exc}"
        ) from exc

    ten_asset = [a.get("name") for a in assets if isinstance(a, dict)]
    for asset in assets:
        if not isinstance(asset, dict) or asset.get("name") != filename:
            continue
        digest = (asset.get("digest") or "").strip()
        if digest.startswith("sha256:"):
            gia_tri = digest.removeprefix("sha256:").strip().lower()
            if len(gia_tri) == 64 and all(c in "0123456789abcdef" for c in gia_tri):
                return gia_tri
            raise ChecksumUnavailableError(
                f"digest của {filename} không phải sha256 hex hợp lệ: {digest!r}"
            )
        raise ChecksumUnavailableError(
            f"bản phát hành v{version} không công bố digest sha256 cho {filename} "
            f"(digest hiện có: {digest!r})"
        )

    raise ChecksumUnavailableError(
        f"không thấy artifact {filename!r} trong bản phát hành v{version} "
        f"(các asset hiện có: {ten_asset})"
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Host được phép phục vụ artifact cập nhật. Bất kỳ chuyển hướng nào ra ngoài
# danh sách này đều bị từ chối (vuln-0014 mục 4).
_HOST_PHAT_HANH_CHO_PHEP: frozenset[str] = frozenset({
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
    "release-assets.githubusercontent.com",
})


def _kiem_host_sau_chuyen_huong(response: object) -> None:
    """Từ chối nếu URL cuối cùng (sau chuyển hướng) không thuộc miền phát hành.

    Vì sao: một chuyển hướng 302 ra host lạ có thể đưa artifact từ nguồn khác
    vào bước cài đặt binary đang chạy. Ngay cả khi checksum sau đó khớp, việc
    tải từ host không mong đợi vẫn là bất thường cần chặn.
    """
    url_cuoi = str(getattr(response, "url", "") or "")
    if not url_cuoi:
        return
    try:
        host = urlparse(url_cuoi).hostname or ""
    except ValueError:
        host = ""
    if host.lower() not in _HOST_PHAT_HANH_CHO_PHEP:
        raise RuntimeError(
            f"tải artifact từ host không được phép: {host or url_cuoi!r} "
            f"(chỉ cho phép: {', '.join(sorted(_HOST_PHAT_HANH_CHO_PHEP))})"
        )


def _read_cache() -> dict[str, object]:
    try:
        with _CACHE_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return cast("dict[str, object]", data)
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110
    return {}


def _write_cache(**fields: object) -> None:
    try:
        cache = _read_cache()
        cache.update(fields)
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110


def skip_version(version: str) -> None:
    """Remember not to prompt again for this version (newer releases still notify)."""
    _write_cache(skipped_version=version)


def _refresh_cache() -> None:
    latest = _fetch_latest_version()
    if latest:
        _write_cache(latest_version=latest, checked_at=time.time())


def start_background_check() -> None:
    """Refresh the cached latest-version info in a daemon thread (at most once per 24h)."""
    global _background_thread  # noqa: PLW0603
    if _is_disabled():
        return
    cache = _read_cache()
    checked_at = cache.get("checked_at")
    if isinstance(checked_at, int | float) and time.time() - checked_at < CHECK_INTERVAL_SECONDS:
        return
    _background_thread = threading.Thread(target=_refresh_cache, daemon=True)
    _background_thread.start()


def get_available_update(*, respect_skip: bool = True) -> str | None:
    """Return the newer version from the cache, or None if up to date / unknown."""
    if _is_disabled():
        return None
    if _background_thread is not None:
        _background_thread.join(timeout=0.2)
    cache = _read_cache()
    latest = cache.get("latest_version")
    current = get_version()
    if not isinstance(latest, str) or current == "unknown" or not _is_newer(latest, current):
        return None
    if respect_skip and cache.get("skipped_version") == latest:
        return None
    return latest


def notify_update(console: Console) -> None:
    latest = get_available_update()
    if not latest:
        return
    console.print(
        f"[#eab308]A new version of strix is available:[/] "
        f"[dim]{get_version()}[/] [dim]→[/] [bold #22c55e]{latest}[/]"
        f"  [dim]·[/]  [#60a5fa]{get_upgrade_command()}[/]"
    )
    console.print()


def run_package_upgrade(console: Console, method: str) -> bool:
    """Upgrade a package-manager install by running its upgrade command."""
    command = get_upgrade_command(method).split()
    console.print(f"[dim]Running[/] [#60a5fa]{' '.join(command)}[/]")
    try:
        result = subprocess.run(command, check=False)  # noqa: S603
    except OSError as e:
        console.print(f"[bold red]Update failed:[/] {e}")
        return False
    if result.returncode != 0:
        console.print(
            f"[bold red]Update failed[/] [dim](exit code {result.returncode}).[/] "
            f"Run it manually: [#60a5fa]{get_upgrade_command(method)}[/]"
        )
        return False
    console.print("[#22c55e]✓ strix updated — restart the scan to use the new version[/]")
    return True


def prompt_update_if_available(console: Console) -> bool:
    """Offer an interactive update before a scan starts.

    Returns True if strix was updated (caller should re-exec / exit).
    """
    latest = get_available_update()
    if not latest or not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    console.print()
    console.print(
        f"[#eab308]A new version of strix is available:[/] "
        f"[dim]{get_version()}[/] [dim]→[/] [bold #22c55e]{latest}[/]"
    )
    console.print(
        "[dim]  y — update now    n — not now (ask again next run)    s — skip this version[/]"
    )
    choice = Prompt.ask("Update strix?", choices=["y", "n", "s"], default="n")
    console.print()
    if choice == "s":
        skip_version(latest)
        return False
    if choice != "y":
        return False
    method = get_install_method()
    if method == "binary":
        return self_update(console, version=latest)
    return run_package_upgrade(console, method)


def restart_env() -> dict[str, str]:
    """Environment for re-exec'ing the binary after a self-update.

    The PyInstaller bootloader marks its child process via environment
    variables (``_MEIPASS2`` on older versions, ``_PYI_*`` on 6.x) that
    point at the already-extracted archive of the *running* version. If
    they leak into the re-exec'd process, the new binary skips extraction
    and runs the old code, so the update never appears to take effect.
    Library-path variables the bootloader overrode are restored from the
    ``*_ORIG`` copies it saved.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key != "_MEIPASS2" and not key.startswith("_PYI_")
    }
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
        orig = env.pop(f"{var}_ORIG", None)
        if orig is not None:
            env[var] = orig
        elif var in os.environ:
            env.pop(var, None)
    return env


def restart_after_update() -> None:
    """Replace the current process with the freshly updated binary."""
    os.execve(sys.executable, sys.argv, restart_env())  # noqa: S606  # nosec B606


def _release_target() -> str | None:
    raw_os = platform.system().lower()
    os_name = {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(raw_os)
    arch = platform.machine().lower()
    arch = {"aarch64": "arm64", "amd64": "x86_64"}.get(arch, arch)
    if os_name is None:
        return None
    target = f"{os_name}-{arch}"
    supported = {
        "linux-x86_64",
        "linux-arm64",
        "macos-x86_64",
        "macos-arm64",
        "windows-x86_64",
    }
    return target if target in supported else None


def _download_and_replace(version: str, target: str, console: Console) -> bool:
    is_windows = target.startswith("windows")
    archive_ext = ".zip" if is_windows else ".tar.gz"
    filename = f"strix-{version}-{target}{archive_ext}"
    url = f"https://github.com/{GITHUB_REPO}/releases/download/v{version}/{filename}"
    binary_name = f"strix-{version}-{target}" + (".exe" if is_windows else "")
    current_exe = Path(sys.executable).resolve()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        archive_path = tmp_dir / filename
        console.print(f"[dim]Downloading[/] {url}")
        with requests.get(  # nosec B113
            url,
            stream=True,
            timeout=REQUEST_TIMEOUT_SECONDS * 12,
            allow_redirects=True,
        ) as response:
            response.raise_for_status()
            # Kiểm host SAU chuyển hướng (vuln-0014 mục 4). Một chuyển hướng 302
            # ra ngoài miền phát hành có thể đưa artifact từ nguồn khác vào bước
            # cài đặt — kể cả khi checksum khớp với release chính thức, việc tải
            # từ host lạ vẫn là điều không mong muốn.
            _kiem_host_sau_chuyen_huong(response)
            with archive_path.open("wb") as f:
                for chunk in response.iter_content(chunk_size=1 << 20):
                    f.write(chunk)

        # XÁC MINH BẮT BUỘC (vuln-0014). Trước đây nhánh này là tuỳ chọn
        # (`if expected_digest: ... else: bỏ qua`), nên chỉ cần nguồn phát hành
        # không trả digest là qua được cổng kiểm tra. Nay fail-closed.
        expected_digest = _fetch_asset_digest(version, filename)
        actual_digest = _sha256_file(archive_path)
        if actual_digest != expected_digest:
            raise RuntimeError(
                f"checksum mismatch for {filename}: "
                f"expected sha256 {expected_digest}, got {actual_digest}"
            )
        logger.info(
            "xác minh checksum thành công cho %s (sha256=%s)", filename, actual_digest
        )

        if is_windows:
            with zipfile.ZipFile(archive_path) as zf:
                zf.extract(binary_name, tmp_dir)
        else:
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extract(binary_name, tmp_dir, filter="data")

        new_binary = tmp_dir / binary_name
        new_binary.chmod(new_binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        staged = current_exe.with_name(current_exe.name + ".new")
        try:
            shutil.copy2(new_binary, staged)
            if is_windows:
                # Windows can't replace a running executable in place; move it aside first.
                old = current_exe.with_name(current_exe.name + ".old")
                old.unlink(missing_ok=True)
                current_exe.rename(old)
                try:
                    staged.replace(current_exe)
                except Exception:
                    old.rename(current_exe)
                    raise
            else:
                staged.replace(current_exe)
        except Exception:
            staged.unlink(missing_ok=True)
            raise
    return True


def self_update(console: Console | None = None, version: str | None = None) -> bool:
    """Replace the running standalone binary with the latest release.

    Returns True on success. For package-manager installs this only
    prints the right upgrade command and returns False.
    """
    console = console or Console()

    if not is_binary_install():
        method = get_install_method()
        console.print(
            f"[#eab308]This strix was installed via {method};[/] "
            f"upgrade it with: [#60a5fa]{get_upgrade_command(method)}[/]"
        )
        return False

    latest = version or _fetch_latest_version()
    if not latest:
        console.print("[bold red]Could not determine the latest strix version.[/]")
        return False

    current = get_version()
    if current != "unknown" and not _is_newer(latest, current):
        console.print(f"[#22c55e]strix {current} is already the latest version.[/]")
        return True

    target = _release_target()
    if not target:
        console.print(
            f"[bold red]No prebuilt binary for this platform "
            f"({platform.system()}/{platform.machine()}).[/]"
        )
        return False

    try:
        _download_and_replace(latest, target, console)
    except Exception as e:  # noqa: BLE001
        logger.debug("self-update failed", exc_info=True)
        console.print(f"[bold red]Update failed:[/] {e}")
        console.print(
            "[dim]You can reinstall manually with:[/] "
            "[#60a5fa]curl -sSL https://strix.ai/install | bash[/]"
        )
        return False

    _write_cache(latest_version=latest, checked_at=time.time())
    console.print(f"[#22c55e]✓ Updated strix to {latest}[/]")
    return True

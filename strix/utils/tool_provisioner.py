"""Cài thêm công cụ khai thác vào sandbox lúc khởi động.

ĐO THỰC TẾ trên sandbox ``strix-sandbox:1.3.0`` cho thấy nhiều công cụ khai
thác quan trọng KHÔNG có sẵn, dù đều nằm trong kho Kali và cài được:

| Thiếu | Dùng để |
|---|---|
| ``dalfox`` | tự động hoá XSS |
| ``commix`` | command injection |
| ``wpscan`` | WordPress (rất phổ biến ở VN) |
| ``exploitdb`` | ``searchsploit`` tra exploit có sẵn |
| ``hydra`` / ``john`` / ``hashcat`` | credential + crack hash |
| ``gobuster`` / ``feroxbuster`` / ``whatweb`` / ``nikto`` | discovery + fingerprint |

================================ HAI CẠM BẪY THẬT ================================

1. **PROXY CỦA CAIDO CHẶN APT/PIP.**
   Strix bơm ``http_proxy=http://127.0.0.1:48080`` (Caido) cho MỌI tiến trình
   trong container, để bắt traffic của agent. Nhưng lúc sandbox vừa lên, Caido
   chưa khởi động xong → ``apt``/``pip`` cố đi qua nó và nhận
   ``Connection refused``. Đo được: ``pip install paramiko`` mất **3 giây** khi
   bỏ proxy, và **thất bại hoàn toàn** khi để nguyên.
   → Vì vậy mọi lệnh cài đặt ở đây phải **xoá sạch biến proxy**.

2. **CÀI TỪNG GÓI VƯỢT TIMEOUT.**
   ``apt-get install`` một gói mất 30-60 giây (giải nén, cấu hình). Cài 8 gói
   tuần tự vượt 420 giây và bị cắt ngang giữa chừng, để lại bộ công cụ dở
   dang. Đo được 486 giây và chỉ xong 5/8 gói.
   → Gộp tất cả gói vào **một lệnh apt duy nhất**, và chạy apt song song pip.

THIẾT KẾ - vì sao chạy nền:
Cài đủ bộ mất vài phút. Chặn cuộc quét từng ấy thời gian ở MỖI lần chạy là cái
giá quá đắt cho việc chỉ cần xong trước khi agent thật sự gọi công cụ. Agent
luôn mất vài lượt đầu cho recon (đọc scope, lập todo, dựng threat model), nên
ta cài song song với giai đoạn đó và ghi trạng thái ra file để agent tự kiểm tra.

Nguyên tắc:
- **Không chặn, không làm hỏng cuộc quét.** Cài hỏng thì agent vẫn chạy tiếp.
- **Cấu hình được.** ``STRIX_PROVISION_TOOLS`` = ``off`` | ``core`` | ``full``.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

#: File trạng thái trong sandbox để agent biết công cụ nào đã sẵn sàng.
SANDBOX_STATUS_PATH = "/workspace/.strix-toolchain.json"

#: Xoá proxy của Caido cho mọi lệnh cài đặt - bắt buộc, xem ghi chú đầu file.
_UNSET_PROXY = (
    "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; "
    'export NO_PROXY="*" no_proxy="*"; '
)

#: Bộ công cụ khai thác thiết yếu, đều có trong kho Kali.
#:
#: THỜI GIAN CÀI ĐO ĐƯỢC (sandbox 1.3.0, mạng thật):
#: ``dalfox`` 8s, ``wpscan`` 8s, ``gobuster`` 8s, ``feroxbuster`` 9s,
#: ``whatweb`` 6s, ``nikto`` 16s, ``exploitdb`` 25s -> tổng ~80 giây.
#:
#: CỐ Ý KHÔNG có ``commix`` ở đây: nó phụ thuộc ``metasploit-framework``, kéo
#: theo 66 gói và mất **250 giây** - gấp ba lần cả bộ còn lại. Với scan mode
#: ``quick`` (~6 phút) thì cài nó là tự sát: container bị xoá trước khi xong.
#: Nó nằm ở nhóm ``full`` cho ai thật sự cần.
_APT_CORE: tuple[str, ...] = (
    "dalfox",  # XSS automation
    "wpscan",  # WordPress
    "exploitdb",  # searchsploit tra exploit có sẵn
    "nikto",  # web server scan
    "whatweb",  # fingerprint
    "gobuster",  # content discovery
    "feroxbuster",  # content discovery (recursive)
)

#: Nhóm nặng hơn, chỉ cài khi bật mức đầy đủ. ``commix`` ở đây vì nó kéo theo
#: metasploit-framework; ``hydra``/``john``/``hashcat`` cho brute-force và
#: crack hash thu được.
_APT_EXTENDED: tuple[str, ...] = (
    "commix",
    "hydra",
    "john",
    "hashcat",
    "wfuzz",
    "sqlmap",
)

#: Thư viện Python agent dùng để tự viết exploit.
_PIP_CORE: tuple[str, ...] = (
    "pwntools",
    "paramiko",
    "pyjwt",
    "scapy",
    "websocket-client",
)

#: Thư viện nặng (playwright kéo theo Chromium ~300 MB).
_PIP_EXTENDED: tuple[str, ...] = ("playwright",)

_PROVISION_LEVELS = frozenset({"off", "core", "full"})

#: Trần thời gian cho mỗi giai đoạn cài đặt (giây).
_APT_TIMEOUT_S = 900
_PIP_TIMEOUT_S = 300


@dataclass
class ProvisionResult:
    """Kết quả một lần cài công cụ."""

    level: str = "off"
    apt_installed: list[str] = field(default_factory=list)
    apt_failed: list[str] = field(default_factory=list)
    pip_installed: list[str] = field(default_factory=list)
    pip_failed: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None

    def ready_tools(self) -> list[str]:
        return [*self.apt_installed, *self.pip_installed]

    def all_failed(self) -> list[str]:
        return [*self.apt_failed, *self.pip_failed]

    def summary(self) -> str:
        return (
            f"mức {self.level}: {len(self.apt_installed)} apt + "
            f"{len(self.pip_installed)} pip OK, "
            f"{len(self.all_failed())} lỗi ({self.duration_s:.0f}s)"
        )

    def to_status_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "state": "error" if self.error else "ready",
            "ready_tools": sorted(self.ready_tools()),
            "failed": sorted(self.all_failed()),
            "duration_seconds": round(self.duration_s, 1),
            "error": self.error,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


def resolve_level(raw: str | None = None) -> str:
    """Mức cài đặt hiệu lực, đọc từ ``STRIX_PROVISION_TOOLS``.

    Mặc định ``core`` - bộ khai thác thiết yếu. Đặt ``full`` để thêm nhóm nặng,
    hoặc ``off`` để tắt hẳn (dùng khi sandbox đã có sẵn công cụ, hoặc khi cần
    quét nhanh mà không muốn chờ cài).
    """
    value = (raw if raw is not None else os.environ.get("STRIX_PROVISION_TOOLS") or "").strip()
    lowered = value.casefold()
    return lowered if lowered in _PROVISION_LEVELS else "core"


def _tools_for(level: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if level == "off":
        return (), ()
    if level == "full":
        return (*_APT_CORE, *_APT_EXTENDED), (*_PIP_CORE, *_PIP_EXTENDED)
    return _APT_CORE, _PIP_CORE


async def _run_in_sandbox(session: Any, script: str, *, timeout_s: float) -> tuple[int, str]:
    """Chạy một script bash trong sandbox, trả (mã thoát, output gộp).

    ``ExecResult`` của SDK có ``stdout: bytes``, ``stderr: bytes``,
    ``exit_code: int``. Gộp cả hai luồng vì ``apt-get`` ghi tiến trình ra stderr.

    API nhận đối số **rời** (``session.exec("bash", "-lc", script)``), không
    phải một list - truyền list sẽ không chạy lệnh.
    """
    wrapped = f"set -o pipefail\n{_UNSET_PROXY}\n{script}"
    try:
        result = await asyncio.wait_for(
            session.exec("bash", "-lc", wrapped, timeout=timeout_s),
            timeout=timeout_s + 60,
        )
    except TimeoutError:
        return 124, "hết thời gian chờ"
    except Exception as exc:  # noqa: BLE001 - sandbox có thể đã chết; cài tool là phụ trợ
        return 1, str(exc)

    exit_code = int(getattr(result, "exit_code", 1) or 0)
    parts: list[str] = []
    for attr in ("stdout", "stderr"):
        raw = getattr(result, attr, None)
        if raw is None:
            continue
        parts.append(raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw))
    return exit_code, "\n".join(parts)


def _apt_script(tools: tuple[str, ...]) -> str:
    """Một lệnh apt DUY NHẤT cho cả bộ - cài tuần tự sẽ vượt timeout.

    ``apt-get update`` PHẢI có ``sudo``: user sandbox là ``pentester`` không
    phải root, và apt cần ghi vào ``/var/lib/apt/lists``. Thiếu ``sudo`` thì
    update thất bại im lặng, danh sách gói rỗng, và mọi gói đều báo lỗi cài.
    """
    names = " ".join(f'"{t}"' for t in tools)
    return f"""
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq 2>&1 | tail -2

# Lọc ra những gói chưa có để apt không phải xử lý lại.
NEEDED=""
for pkg in {names}; do
  if command -v "$pkg" >/dev/null 2>&1; then
    echo "SKIP $pkg"
  else
    NEEDED="$NEEDED $pkg"
  fi
done

if [ -z "$NEEDED" ]; then
  echo "DONE (tất cả đã có)"
  exit 0
fi

echo "Cài:$NEEDED"
if sudo -E apt-get install -y -qq --no-install-recommends $NEEDED >/dev/null 2>&1; then
  echo "BATCH-OK"
else
  echo "BATCH-FAIL"
  # Cài lại từng gói để biết chính xác gói nào hỏng, và cứu được phần còn lại.
  for pkg in $NEEDED; do
    if sudo -E apt-get install -y -qq --no-install-recommends "$pkg" >/dev/null 2>&1; then
      echo "OK $pkg"
    else
      echo "FAIL $pkg"
    fi
  done
  exit 0
fi

for pkg in $NEEDED; do
  echo "OK $pkg"
done
"""


def _pip_script(packages: tuple[str, ...]) -> str:
    names = " ".join(f'"{p}"' for p in packages)
    return f"""
PIP=$(command -v pip3 || command -v pip)
if [ -z "$PIP" ]; then echo "FAIL pip"; exit 0; fi
# Proxy của Caido làm pip không ra được mạng (xem ghi chú đầu file).
$PIP install --no-cache-dir --quiet --proxy "" {names} 2>&1 | tail -3
for pkg in {names}; do
  module=$(echo "$pkg" | tr '-' '_')
  CHECK="import importlib.util,sys; "
  CHECK="$CHECK sys.exit(0 if importlib.util.find_spec('$module') else 1)"
  if python3 -c "$CHECK" \\
       >/dev/null 2>&1 || $PIP show "$pkg" >/dev/null 2>&1; then
    echo "OK $pkg"
  else
    echo "FAIL $pkg"
  fi
done
"""


def _parse_output(output: str) -> tuple[list[str], list[str]]:
    """Tách dòng ``OK x`` / ``FAIL x`` / ``SKIP x`` thành hai danh sách."""
    ok: list[str] = []
    failed: list[str] = []
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("OK "):
            ok.append(stripped[3:].strip())
        elif stripped.startswith("FAIL "):
            failed.append(stripped[5:].strip())
        elif stripped.startswith("SKIP "):
            # Đã có sẵn cũng tính là sẵn sàng.
            ok.append(stripped[5:].split(" ", 1)[0].strip())
    return ok, failed


async def _write_status(session: Any, result: ProvisionResult) -> None:
    try:
        payload = json.dumps(result.to_status_dict(), ensure_ascii=False, indent=2)
        await session.write(Path(SANDBOX_STATUS_PATH), io.BytesIO(payload.encode("utf-8")))
    except Exception as exc:  # noqa: BLE001 - trạng thái là phụ trợ, không chặn scan
        logger.debug("ghi trạng thái toolchain thất bại: %s", exc)


async def provision_toolchain(session: Any, *, level: str | None = None) -> ProvisionResult:
    """Cài công cụ khai thác vào sandbox. Không bao giờ ném lỗi ra ngoài."""
    resolved = resolve_level(level)
    result = ProvisionResult(level=resolved)
    if resolved == "off" or session is None:
        return result

    apt_tools, pip_packages = _tools_for(resolved)
    started = time.monotonic()
    logger.info(
        "Bắt đầu cài công cụ (mức %s): %d apt + %d pip",
        resolved,
        len(apt_tools),
        len(pip_packages),
    )

    try:
        # apt và pip độc lập nhau -> chạy song song, tổng thời gian bằng cái chậm
        # nhất thay vì tổng hai giai đoạn.
        apt_coro = _run_in_sandbox(session, _apt_script(apt_tools), timeout_s=_APT_TIMEOUT_S)
        pip_coro = _run_in_sandbox(session, _pip_script(pip_packages), timeout_s=_PIP_TIMEOUT_S)
        apt_out, pip_out = await asyncio.gather(apt_coro, pip_coro, return_exceptions=True)

        if isinstance(apt_out, BaseException):
            result.apt_failed = list(apt_tools)
            logger.debug("apt giai đoạn lỗi: %s", apt_out)
        else:
            code, out = apt_out
            result.apt_installed, result.apt_failed = _parse_output(out)
            if code == 124:
                result.apt_failed.append("(apt hết thời gian)")

        if isinstance(pip_out, BaseException):
            result.pip_failed = list(pip_packages)
            logger.debug("pip giai đoạn lỗi: %s", pip_out)
        else:
            code, out = pip_out
            result.pip_installed, result.pip_failed = _parse_output(out)
            if code == 124:
                result.pip_failed.append("(pip hết thời gian)")
    except Exception as exc:
        logger.exception("cài công cụ thất bại")
        result.error = str(exc)
    finally:
        result.duration_s = time.monotonic() - started

    await _write_status(session, result)
    logger.info("Cài công cụ xong: %s", result.summary())
    return result


def start_provisioning(session: Any, *, level: str | None = None) -> asyncio.Task[ProvisionResult]:
    """Khởi động cài công cụ ở NỀN, trả task để theo dõi.

    Trả về ngay để cuộc quét không phải chờ. Task tự ghi trạng thái ra
    ``/workspace/.strix-toolchain.json`` cho agent đọc.
    """

    async def _runner() -> ProvisionResult:
        try:
            return await provision_toolchain(session, level=level)
        except Exception as exc:
            logger.exception("task cài công cụ sập")
            return ProvisionResult(level=resolve_level(level), error=str(exc))

    return asyncio.create_task(_runner(), name="strix-provision-toolchain")

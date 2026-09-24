"""Thu hoạch chứng cứ từ sandbox trước khi container bị xoá.

VẤN ĐỀ: sandbox là container dùng-một-lần. Mọi thứ agent tạo ra trong đó —
ảnh chụp màn hình, output sqlmap, file nmap XML, request/response HTTP thật —
đều bị xoá sạch khi quét xong. Báo cáo chỉ còn lại phần CHỮ mà agent tự thuật.

Hệ quả với người nhận báo cáo: họ được yêu cầu tin vào một đoạn văn, không có
gì để tự mắt kiểm chứng. Với một phát hiện bảo mật, đó là điểm yếu chí mạng.

================================================================================
BÀI HỌC ĐÃ TRẢ GIÁ VỀ API CỦA SDK (đọc trước khi sửa file này)
================================================================================

Lần đầu tôi dùng ``session.extract(path, buf, compression_scheme="tar")`` và
tưởng nó KÉO file ra. Sai hoàn toàn. Đo thực tế trong log:

    extract(/workspace/.agent-browser-screenshots) thất bại:
        failed to write archive for path: /workspace/.agent-browser-screenshots
    extract(/workspace) thất bại: manifest path must be relative: /

``extract`` là chiều NGƯỢC LẠI — nó GIẢI NÉN một archive VÀO trong sandbox
(upload). Không có gì được kéo ra, nên thu hoạch luôn ra 0 file.

Chiều đúng để LẤY dữ liệu ra:

- ``session.persist_workspace() -> io.IOBase``
  Trả về một **tar stream của toàn bộ workspace**, với đường dẫn thành viên
  tương đối so với workspace root. Một lượt gọi, lấy hết cây. Đây là thứ dùng
  cho chứng cứ.
- ``session.read(path) -> io.IOBase``
  Đọc MỘT file. Dùng khi chỉ cần vài file cụ thể.

Cả hai nhận ``user=`` để chạy dưới user sandbox.

Vì ``persist_workspace`` gói cả workspace, nó cũng gói cả những thứ KHÔNG phải
chứng cứ (mã nguồn target, ``.git``, file tạm). Việc lọc nằm ở ``_is_evidence``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    import io
    from collections.abc import Iterable


from strix.tools.proxy import caido_api


logger = logging.getLogger(__name__)

#: Thư mục gốc trong sandbox chứa ảnh chụp của agent-browser (tương đối workspace).
SANDBOX_SCREENSHOT_REL = ".agent-browser-screenshots"
#: Nơi output tool quá lớn được spill ra.
SANDBOX_TOOL_OUTPUT_REL = ".tool-output"

#: Đuôi file được coi là chứng cứ đáng thu hoạch.
_IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
_EVIDENCE_SUFFIXES = (
    *_IMAGE_SUFFIXES,
    ".xml",
    ".json",
    ".txt",
    ".csv",
    ".log",
    ".har",
    ".html",
    ".htm",
    ".md",
    ".sql",
    ".pcap",
    ".pcapng",
    ".req",
    ".resp",
    ".nmap",
    ".gnmap",
    ".out",
)

#: Tên file/thư mục bỏ qua — rác, không phải chứng cứ.
_SKIP_NAMES = frozenset(
    {
        "__pycache__",
        "node_modules",
        ".git",
        "db.sqlite",
        "db.sqlite-journal",
        "db.sqlite-wal",
        "db.sqlite-shm",
    }
)

#: Tiền tố thư mục bỏ qua khi duyệt (target source, không phải chứng cứ).
_SKIP_DIR_PREFIXES = (
    "node_modules/",
    "__pycache__/",
    ".git/",
    "venv/",
    ".venv/",
)

#: Trần an toàn cho một lần thu hoạch.
_MAX_FILES = 500
_MAX_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB
_MAX_SINGLE_FILE_BYTES = 64 * 1024 * 1024  # 64 MB


class _Budget:
    """Trần số file và dung lượng cho một lần thu hoạch."""

    def __init__(self, max_files: int = _MAX_FILES, max_bytes: int = _MAX_TOTAL_BYTES) -> None:
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.files = 0
        self.bytes = 0
        self.rejected: list[str] = []

    def take(self, name: str, size: int) -> bool:
        if self.files >= self.max_files:
            self.rejected.append(f"{name} (quá số file)")
            return False
        if size > _MAX_SINGLE_FILE_BYTES:
            self.rejected.append(f"{name} (file quá lớn: {size} byte)")
            return False
        if self.bytes + size > self.max_bytes:
            self.rejected.append(f"{name} (quá tổng dung lượng)")
            return False
        self.files += 1
        self.bytes += size
        return True


@dataclass
class HarvestedEvidence:
    """Kết quả một lần thu hoạch."""

    screenshots: list[Path] = field(default_factory=list)
    http_exchanges: list[Path] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    total_bytes: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.screenshots) + len(self.http_exchanges) + len(self.artifacts)

    def human_bytes(self) -> str:
        size = float(self.total_bytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} GB"

    def summary(self) -> str:
        return (
            f"{len(self.screenshots)} ảnh, {len(self.http_exchanges)} HTTP, "
            f"{len(self.artifacts)} artifact ({self.human_bytes()})"
        )


def evidence_root(run_dir: Path) -> Path:
    """Thư mục chứng cứ của một lần quét."""
    return run_dir / "evidence"


def _is_evidence(rel: str) -> bool:
    """File này có đáng thu hoạch không, tính theo đường dẫn tương đối workspace."""
    if not rel or rel.endswith("/"):
        return False
    lowered = rel.casefold()
    if any(lowered.startswith(prefix) for prefix in _SKIP_DIR_PREFIXES):
        return False
    name = Path(lowered).name
    if name in _SKIP_NAMES:
        return False
    # File ẩn chỉ nhận nếu là ảnh (ảnh nằm trong thư mục ẩn của agent-browser).
    if name.startswith(".") and not name.endswith(_IMAGE_SUFFIXES):
        return False
    return lowered.endswith(_EVIDENCE_SUFFIXES)


def _destination_for(rel: str) -> tuple[str, str]:
    """Trả (nhóm, đường dẫn con) cho một file chứng cứ."""
    lowered = rel.casefold()
    if lowered.startswith(f"{SANDBOX_SCREENSHOT_REL}/") or lowered.endswith(_IMAGE_SUFFIXES):
        return "screenshots", Path(rel).name
    if lowered.startswith(f"{SANDBOX_TOOL_OUTPUT_REL}/"):
        return "tool-output", str(Path(rel).relative_to(SANDBOX_TOOL_OUTPUT_REL))
    return "artifacts", rel


def _unpack_workspace_archive(
    archive: io.IOBase,
    dest_root: Path,
    budget: _Budget,
) -> tuple[list[Path], list[Path], list[Path]]:
    """Giải nén tar workspace, phân loại vào screenshots/tool-output/artifacts."""
    screenshots: list[Path] = []
    tool_output: list[Path] = []
    artifacts: list[Path] = []

    with tarfile.open(fileobj=archive, mode="r|*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            # removeprefix chứ KHÔNG lstrip: lstrip('./') xoá mọi ký tự
            # '.' và '/' ở đầu, làm mất dấu chấm của '.tool-output'.
            rel = member.name.removeprefix("./")
            if not _is_evidence(rel):
                continue
            if not budget.take(rel, member.size):
                continue

            group, sub = _destination_for(rel)
            # Chặn thoát thư mục: chỉ nhận đường dẫn tương đối an toàn.
            safe_parts = [p for p in Path(sub).parts if p not in {"..", ".", "/", ""}]
            if not safe_parts:
                continue
            target = dest_root / group / Path(*safe_parts)
            target.parent.mkdir(parents=True, exist_ok=True)

            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            with target.open("wb") as fh:
                shutil.copyfileobj(extracted, fh)

            if group == "screenshots":
                screenshots.append(target)
            elif group == "tool-output":
                tool_output.append(target)
            else:
                artifacts.append(target)

    return screenshots, tool_output, artifacts


async def _harvest_workspace(
    session: Any, dest_root: Path, budget: _Budget
) -> tuple[list[Path], list[Path], list[Path]]:
    """Lấy toàn bộ workspace qua ``persist_workspace`` rồi phân loại."""
    try:
        archive = await session.persist_workspace()
    except Exception as exc:  # noqa: BLE001 - thu hoạch là phụ trợ
        logger.debug("persist_workspace thất bại: %s", exc)
        return [], [], []

    try:
        return await asyncio.to_thread(_unpack_workspace_archive, archive, dest_root, budget)
    except Exception as exc:  # noqa: BLE001 - tar hỏng không được làm sập
        logger.debug("giải nén workspace thất bại: %s", exc)
        return [], [], []
    finally:
        with contextlib.suppress(Exception):
            archive.close()  # type: ignore[attr-defined]


def _decode(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _format_exchange(request_id: str, title: str, result: Any) -> str:
    request = getattr(result, "request", None) or result
    response = getattr(result, "response", None)
    raw_request = _decode(getattr(request, "raw", None))
    raw_response = _decode(getattr(response, "raw", None) if response is not None else None)
    return (
        f"# HTTP exchange {request_id}\n"
        f"# Nguồn: Caido proxy trong sandbox\n"
        f"# Phát hiện: {title}\n\n"
        f"{'=' * 72}\nREQUEST\n{'=' * 72}\n{raw_request}\n\n"
        f"{'=' * 72}\nRESPONSE\n{'=' * 72}\n{raw_response}\n"
    )


async def _harvest_http(
    caido_client: Any,
    reports: list[dict[str, Any]],
    dest: Path,
    budget: _Budget,
) -> list[Path]:
    """Lưu request/response HTTP thô cho các phát hiện có trích dẫn proxy.

    Báo cáo chỉ lưu ``http_exchange_ids`` — con số trỏ vào Caido trong sandbox.
    Sau khi container bị xoá, con số đó vô nghĩa.
    """
    written: list[Path] = []
    if caido_client is None:
        return written

    seen: set[str] = set()
    for report in reports:
        ids = report.get("http_exchange_ids") or []
        if not isinstance(ids, list):
            continue
        title = str(report.get("title") or "không rõ")
        for raw_id in ids:
            key = str(raw_id).strip()
            if not key or key in seen:
                continue
            seen.add(key)

            try:
                result = await caido_api.get_request_with_client(caido_client, key)
            except Exception as exc:  # noqa: BLE001 - một id hỏng không chặn phần còn lại
                logger.debug("lấy HTTP exchange %s thất bại: %s", key, exc)
                continue
            if result is None:
                continue

            payload = _format_exchange(key, title, result)
            encoded = payload.encode("utf-8")
            if not budget.take(f"exchange-{key}.txt", len(encoded)):
                continue

            dest.mkdir(parents=True, exist_ok=True)
            target = dest / f"exchange-{key}.txt"
            target.write_text(payload, encoding="utf-8")
            written.append(target)

    return written


async def harvest_evidence(
    *,
    session: Any,
    run_dir: Path,
    reports: Iterable[dict[str, Any]] = (),
    caido_client: Any = None,
) -> HarvestedEvidence:
    """Thu hoạch toàn bộ chứng cứ từ sandbox còn sống.

    Gọi hàm này NGAY TRƯỚC ``session_manager.cleanup``. Hàm không bao giờ ném
    lỗi ra ngoài — thu hoạch hỏng không được làm hỏng cuộc quét.
    """
    result = HarvestedEvidence()
    if session is None:
        return result

    root = evidence_root(run_dir)
    budget = _Budget()
    report_list = [r for r in reports if isinstance(r, dict)]

    try:
        root.mkdir(parents=True, exist_ok=True)

        result.screenshots, tool_output, result.artifacts = await _harvest_workspace(
            session, root, budget
        )
        result.artifacts.extend(tool_output)

        result.http_exchanges = await _harvest_http(
            caido_client, report_list, root / "http", budget
        )

        result.rejected = budget.rejected
        result.total_bytes = budget.bytes
    except Exception as exc:
        logger.exception("thu hoạch chứng cứ thất bại")
        result.errors.append(str(exc))

    logger.info("Thu hoạch chứng cứ: %s (thư mục %s)", result.summary(), root)
    return result

"""Thu hoạch chứng cứ từ sandbox trước khi container bị xoá.

VẤN ĐỀ: sandbox là container dùng-một-lần. Mọi thứ agent tạo ra trong đó —
ảnh chụp màn hình, output sqlmap, file nmap XML, request/response HTTP thật —
đều bị xoá sạch khi quét xong. Báo cáo chỉ còn lại phần CHỮ mà agent tự thuật.

Hệ quả với người nhận báo cáo: họ được yêu cầu tin vào một đoạn văn, không có
gì để tự mắt kiểm chứng. Với một phát hiện bảo mật, đó là điểm yếu chí mạng —
chủ hệ thống cần thấy tận mắt, không phải đọc lời kể.

Module này chạy NGAY TRƯỚC khi container bị xoá, copy bằng chứng thật ra
``run_dir/evidence/`` để nó sống sót và tới được tay người nhận.

Nguyên tắc:
- **Không bao giờ làm hỏng cuộc quét.** Mọi lỗi đều bị nuốt và ghi log; thu
  hoạch là việc phụ trợ, không phải điều kiện thành công.
- **Chỉ đọc.** Không sửa, không xoá gì trong sandbox.
- **Có trần.** Giới hạn số file và tổng dung lượng, tránh kéo về hàng GB.
"""

from __future__ import annotations

import asyncio
import io
import logging
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Iterable


from strix.tools.proxy import caido_api


logger = logging.getLogger(__name__)

#: Thư mục gốc trong sandbox chứa ảnh chụp của agent-browser.
SANDBOX_SCREENSHOT_DIR = "/workspace/.agent-browser-screenshots"
#: Nơi output tool quá lớn được spill ra.
SANDBOX_TOOL_OUTPUT_DIR = "/workspace/.tool-output"

#: Đuôi file được coi là chứng cứ đáng thu hoạch.
_IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
_EVIDENCE_SUFFIXES = (*_IMAGE_SUFFIXES,
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
)

#: Tên file/thư mục bỏ qua — rác hoặc không phải chứng cứ.
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


def _is_evidence_candidate(name: str) -> bool:
    lowered = name.casefold()
    if lowered in _SKIP_NAMES:
        return False
    if lowered.startswith(".") and not lowered.endswith(_IMAGE_SUFFIXES):
        # File ẩn thường là metadata; ảnh trong thư mục ẩn vẫn nhận.
        return False
    return lowered.endswith(_EVIDENCE_SUFFIXES)


def _safe_relative(member_name: str, base: str) -> Path:
    """Đường dẫn tương đối an toàn, chặn thoát khỏi thư mục đích."""
    raw = Path(member_name)
    try:
        rel = raw.relative_to(base)
    except ValueError:
        rel = Path(raw.name)
    parts = [p for p in rel.parts if p not in {"..", ".", "/", ""}]
    return Path(*parts) if parts else Path(raw.name)


async def _extract_dir(session: Any, sandbox_path: str, dest: Path, budget: _Budget) -> list[Path]:
    """Kéo một cây thư mục trong sandbox về ``dest``.

    Dùng ``session.extract`` với tar: một lượt gọi cho cả cây, thay vì
    ``ls`` + ``read`` từng file (chậm và dễ đứt giữa dòng).
    """
    try:
        buf = io.BytesIO()
        await session.extract(Path(sandbox_path), buf, compression_scheme="tar")
    except Exception as exc:  # noqa: BLE001 - thư mục có thể không tồn tại
        logger.debug("extract(%s) thất bại: %s", sandbox_path, exc)
        return []

    buf.seek(0)

    def _unpack() -> list[Path]:
        out: list[Path] = []
        with tarfile.open(fileobj=buf, mode="r:") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                name = Path(member.name).name
                if not _is_evidence_candidate(name):
                    continue
                if not budget.take(member.name, member.size):
                    continue
                target = dest / _safe_relative(member.name, sandbox_path)
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                with target.open("wb") as fh:
                    shutil.copyfileobj(extracted, fh)
                out.append(target)
        return out

    try:
        return await asyncio.to_thread(_unpack)
    except Exception as exc:  # noqa: BLE001 - tar hỏng không được làm sập
        logger.debug("giải nén tar của %s thất bại: %s", sandbox_path, exc)
        return []


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
    Sau khi container bị xoá, con số đó vô nghĩa. Ở đây ta chụp lại nội dung
    thật để bằng chứng còn đọc được về sau.
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

        # 1) Ảnh chụp màn hình — chứng cứ trực quan giá trị nhất.
        result.screenshots = await _extract_dir(
            session, SANDBOX_SCREENSHOT_DIR, root / "screenshots", budget
        )

        # 2) Output tool bị spill (kết quả quét dài).
        result.artifacts.extend(
            await _extract_dir(session, SANDBOX_TOOL_OUTPUT_DIR, root / "tool-output", budget)
        )

        # 3) Artifact khác agent tạo trong /workspace.
        result.artifacts.extend(
            await _extract_dir(session, "/workspace", root / "artifacts", budget)
        )

        # 4) HTTP request/response thô cho phát hiện có trích dẫn proxy.
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

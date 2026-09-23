"""Cưỡng chế phạm vi (scope) ở tầng code.

Vấn đề: Strix cưỡng chế scope **chỉ bằng prompt**. Mọi tool mạng
(``repeat_request``, ``web_get_contents``, …) đều nhận URL/host tuỳ ý, và
``repeat_request`` cho phép thay hẳn URL qua ``modifications["url"]``. Một model
bị prompt-injection hoặc chỉ đơn giản là đi lạc có thể quét ra ngoài phạm vi
được uỷ quyền — rủi ro pháp lý trực tiếp cho người vận hành.

Module này port logic từ PentestGPT ``plan.py`` (``_canonical_url_target``,
``_url_contains``, ``_target_is_allowed``) và bổ sung phần xử lý host trần / IP
mà scan config của Strix sinh ra.

Nguyên tắc:
- **Chuẩn hoá chặt trước khi so**: từ chối URL có userinfo, fragment, dấu ``\\``,
  ký tự điều khiển, ``%`` còn sót sau giải mã, và đoạn ``..``. Đây là các vector
  vòng qua so khớp tiền tố quen thuộc.
- **Chỉ mở rộng trong phạm vi đã duyệt**: so khớp origin (scheme + host + port)
  chính xác, rồi mới tới tiền tố đường dẫn.
- **Không kết luận khi không có dữ liệu**: nếu scan không khai báo target mạng
  nào (ví dụ chỉ quét source code), không chặn gì cả.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


logger = logging.getLogger(__name__)

#: Scheme được phép cùng cổng mặc định.
_DEFAULT_PORT: dict[str, int] = {"http": 80, "https": 443}

#: Số vòng giải mã phần trăm tối đa khi chuẩn hoá đường dẫn.
#: Nhiều hơn thế là dấu hiệu của chuỗi mã hoá lồng nhau nhằm lách so khớp.
_MAX_PERCENT_DECODE_ROUNDS = 4


class ScopeViolationError(ValueError):
    """Target nằm ngoài phạm vi được uỷ quyền."""


@dataclass(frozen=True)
class CanonicalTarget:
    """Target đã chuẩn hoá, dùng để so khớp phạm vi."""

    #: ``("url", scheme, host, port)`` hoặc ``("host", host, port)``.
    kind: str
    scheme: str
    host: str
    port: int
    #: Các đoạn đường dẫn đã giải mã (rỗng với target dạng host trần).
    segments: tuple[str, ...]

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    def describe(self) -> str:
        if self.kind == "url":
            return f"{self.scheme}://{self.host}:{self.port}"
        return f"{self.host}:{self.port}"


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _canonical_host_port(raw: str) -> tuple[str, int] | None:
    """Chuẩn hoá ``host`` hoặc ``host:port`` (không scheme)."""
    if not raw or raw != raw.strip() or "\\" in raw:
        return None
    # Dấu '/' nghĩa là đây là đường dẫn (checkout source cục bộ), không phải
    # host. Nhận nhầm sẽ biến '/workspace/x' thành một target mạng giả.
    if "/" in raw:
        return None
    if _has_control_characters(raw) or any(character.isspace() for character in raw):
        return None
    if raw.count(":") > 1 and not raw.startswith("["):
        # IPv6 trần không có ngoặc: không đoán, từ chối cho an toàn.
        return None

    host = raw
    port: int | None = None
    if raw.startswith("["):
        closing = raw.find("]")
        if closing < 0:
            return None
        host = raw[1:closing]
        remainder = raw[closing + 1 :]
        if remainder:
            if not remainder.startswith(":"):
                return None
            try:
                port = int(remainder[1:])
            except ValueError:
                return None
    elif ":" in raw:
        host, _, port_text = raw.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            return None

    if not host:
        return None
    if port is not None and not (1 <= port <= 65535):
        return None
    # Cổng 0 nghĩa là "không nêu cổng"; dùng 0 làm giá trị đánh dấu.
    return host.casefold().rstrip("."), port if port else 0


def canonicalize_target(raw: str) -> CanonicalTarget | None:
    """Chuẩn hoá một target thành dạng so khớp được, hoặc ``None`` nếu không hợp lệ.

    Chấp nhận URL ``http(s)://`` và dạng host trần / ``host:port`` / IP (Strix
    sinh ra cả hai từ scan config).
    """
    if not raw:
        return None
    value = raw.strip()
    # Khoảng trắng thừa ở đầu/cuối là dấu hiệu chuỗi bị ghép — từ chối thay vì
    # tự ý cắt, vì cắt có thể che một host khác phía sau.
    if not value or value != raw:
        return None
    if "\\" in value or _has_control_characters(value):
        return None

    if "://" not in value:
        parsed_host = _canonical_host_port(value)
        if parsed_host is None:
            return None
        host, port = parsed_host
        return CanonicalTarget(kind="host", scheme="", host=host, port=port, segments=())

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.casefold()
        hostname = parsed.hostname
        if scheme not in _DEFAULT_PORT or hostname is None:
            return None
        # userinfo và fragment là vector kinh điển để lách so khớp host.
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            return None
        port = parsed.port if parsed.port is not None else _DEFAULT_PORT[scheme]
        # urlsplit ném ValueError với cổng ngoài 1..65535, nhưng cổng 0 thì lọt.
        if not (1 <= port <= 65535):
            return None
    except (UnicodeError, ValueError):
        return None

    path = parsed.path or "/"
    try:
        for _ in range(_MAX_PERCENT_DECODE_ROUNDS):
            decoded = unquote(path, errors="strict")
            if decoded == path:
                break
            path = decoded
        # Còn '%' nghĩa là giải mã chưa hết (hoặc mã hoá lồng nhau) -> từ chối.
        if unquote(path, errors="strict") != path:
            return None
    except UnicodeDecodeError:
        return None

    if not path.startswith("/") or "%" in path or "\\" in path or _has_control_characters(path):
        return None

    segments = tuple(segment for segment in path.split("/") if segment)
    # '.' hoặc '..' (kể cả kèm tham số kiểu '..;x') là ý đồ vượt phạm vi.
    if any(segment.split(";", 1)[0] in {".", ".."} for segment in segments):
        return None

    return CanonicalTarget(
        kind="url",
        scheme=scheme,
        host=hostname.casefold().rstrip("."),
        port=port,
        segments=segments,
    )


def target_within(allowed: CanonicalTarget, candidate: CanonicalTarget) -> bool:
    """``candidate`` có nằm trong ``allowed`` không.

    Target dạng URL: phải cùng origin, và đường dẫn của candidate phải nằm dưới
    đường dẫn của allowed (so theo đoạn, không so theo ký tự — ``/api`` không
    được coi là chứa ``/apix``).

    Target dạng host trần: cùng host, và cổng phải khớp khi allowed có nêu cổng.
    """
    if allowed.kind == "host":
        if candidate.host != allowed.host:
            return False
        return not (allowed.port and candidate.port and candidate.port != allowed.port)

    if candidate.kind != "url":
        return False
    if allowed.origin != candidate.origin:
        return False
    return candidate.segments[: len(allowed.segments)] == allowed.segments


def authorized_network_targets(authorized: list[str]) -> list[CanonicalTarget]:
    """Lọc ra các target mạng so khớp được từ danh sách được uỷ quyền.

    Đường dẫn cục bộ (checkout source) không phải target mạng nên bị bỏ qua.
    """
    out: list[CanonicalTarget] = []
    for raw in authorized:
        if not isinstance(raw, str) or not raw.strip():
            continue
        canonical = canonicalize_target(raw)
        if canonical is not None:
            out.append(canonical)
    return out


def check_target_in_scope(
    candidate: str,
    authorized: list[str],
) -> tuple[bool, str]:
    """Kiểm tra ``candidate`` có thuộc phạm vi ``authorized`` không.

    Trả về ``(True, "")`` nếu hợp lệ, hoặc ``(False, lý_do)`` nếu vi phạm.

    Khi ``authorized`` không có target mạng nào (scan chỉ đọc source code),
    trả về hợp lệ — không có phạm vi mạng nào để cưỡng chế.
    """
    allowed_targets = authorized_network_targets(authorized)
    if not allowed_targets:
        return True, ""

    canonical = canonicalize_target(candidate)
    if canonical is None:
        # Không chuẩn hoá được thì không thể chứng minh là trong phạm vi.
        return False, (
            f"Target {candidate!r} không chuẩn hoá được để đối chiếu phạm vi "
            "(URL/host có dạng không hợp lệ hoặc chứa thành phần gây nhập nhằng)."
        )

    if any(target_within(allowed, canonical) for allowed in allowed_targets):
        return True, ""

    allowed_desc = ", ".join(sorted({target.describe() for target in allowed_targets}))
    return False, (
        f"Target {candidate!r} nằm NGOÀI phạm vi được uỷ quyền. "
        f"Phạm vi cho phép: {allowed_desc}. "
        "Không được kiểm thử tài sản ngoài danh sách này."
    )

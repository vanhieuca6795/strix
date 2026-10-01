"""Test cho harness thu hoạch chứng cứ (GĐ4).

Trọng tâm: chứng minh chứng cứ sống sót qua teardown sandbox, và không bao
giờ làm hỏng cuộc quét dù thu hoạch gặp sự cố.

GHI CHÚ API: harvester dùng ``session.persist_workspace()`` — trả về tar stream
của TOÀN BỘ workspace. Bản đầu dùng nhầm ``session.extract()`` (chiều ngược
lại: giải nén VÀO sandbox) nên thu hoạch luôn ra 0 file. Fake dưới đây mô phỏng
đúng ``persist_workspace``.
"""

from __future__ import annotations

import io
import shutil
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from strix.core import runner
from strix.runtime.caido_handle import CaidoBootstrapHandle
from strix.tools.proxy import caido_api
from strix.utils import evidence_harvester as h


class _FakeSession:
    """Sandbox giả: ``persist_workspace`` trả tar của workspace đã định sẵn."""

    def __init__(self, files: dict[str, bytes] | None = None, *, boom: bool = False) -> None:
        self.files = files or {}
        self.boom = boom
        self.persist_calls = 0

    async def persist_workspace(self) -> io.IOBase:
        self.persist_calls += 1
        if self.boom:
            raise RuntimeError("sandbox died")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name, payload in self.files.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
        buf.seek(0)
        return buf


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run-abc"
    d.mkdir()
    return d


class TestHarvestScreenshots:
    @pytest.mark.asyncio
    async def test_copies_screenshots(self, run_dir: Path) -> None:
        session = _FakeSession(
            {
                ".agent-browser-screenshots/page1.png": b"\x89PNG-fake-1",
                ".agent-browser-screenshots/page2.png": b"\x89PNG-fake-2",
            }
        )

        result = await h.harvest_evidence(session=session, run_dir=run_dir)

        assert len(result.screenshots) == 2
        saved = run_dir / "evidence" / "screenshots" / "page1.png"
        assert saved.read_bytes() == b"\x89PNG-fake-1"

    @pytest.mark.asyncio
    async def test_screenshot_bytes_are_binary_exact(self, run_dir: Path) -> None:
        payload = bytes(range(256)) * 8
        session = _FakeSession({".agent-browser-screenshots/shot.png": payload})

        await h.harvest_evidence(session=session, run_dir=run_dir)

        saved = run_dir / "evidence" / "screenshots" / "shot.png"
        assert saved.read_bytes() == payload

    @pytest.mark.asyncio
    async def test_unrelated_files_not_collected(self, run_dir: Path) -> None:
        session = _FakeSession(
            {
                "app.py": b"print('target source')",
                ".agent-browser-screenshots/shot.png": b"png",
            }
        )
        result = await h.harvest_evidence(session=session, run_dir=run_dir)
        assert len(result.screenshots) == 1
        # `app.py` là mã nguồn target, không phải chứng cứ của cuộc kiểm thử.
        assert all("app.py" not in str(p) for p in result.artifacts)


class TestHarvestArtifacts:
    @pytest.mark.asyncio
    async def test_copies_tool_output_and_other_evidence(self, run_dir: Path) -> None:
        session = _FakeSession(
            {
                ".tool-output/out1.txt": b"nmap result",
                "scan.xml": b"<nmaprun/>",
                "junk.bin": b"\x00\x01",
            }
        )

        result = await h.harvest_evidence(session=session, run_dir=run_dir)

        assert len(result.artifacts) == 2
        assert (run_dir / "evidence" / "artifacts" / "scan.xml").read_bytes() == b"<nmaprun/>"
        assert (run_dir / "evidence" / "tool-output" / "out1.txt").read_bytes() == b"nmap result"
        # Đuôi không nằm trong danh sách chứng cứ thì bỏ qua.
        assert not (run_dir / "evidence" / "artifacts" / "junk.bin").exists()

    @pytest.mark.asyncio
    async def test_skips_database_files(self, run_dir: Path) -> None:
        session = _FakeSession(
            {
                "db.sqlite": b"SQLite format 3",
                "keep.json": b"{}",
            }
        )
        result = await h.harvest_evidence(session=session, run_dir=run_dir)
        assert len(result.artifacts) == 1
        assert (run_dir / "evidence" / "artifacts" / "keep.json").exists()

    @pytest.mark.asyncio
    async def test_skips_target_source_directories(self, run_dir: Path) -> None:
        session = _FakeSession(
            {
                "node_modules/pkg/index.js": b"// dep",
                "__pycache__/mod.pyc": b"\x00",
                ".git/config": b"[core]",
                "report.md": b"# real evidence",
            }
        )
        result = await h.harvest_evidence(session=session, run_dir=run_dir)
        names = [p.name for p in result.artifacts]
        assert names == ["report.md"]


class TestSafetyBounds:
    @pytest.mark.asyncio
    async def test_oversized_file_rejected(self, run_dir: Path) -> None:
        huge = b"x" * (h._MAX_SINGLE_FILE_BYTES + 1)
        session = _FakeSession({"huge.txt": huge})
        result = await h.harvest_evidence(session=session, run_dir=run_dir)
        assert result.artifacts == []
        assert result.rejected, "file quá lớn phải bị ghi nhận là đã từ chối"

    @pytest.mark.asyncio
    async def test_path_traversal_is_contained(self, run_dir: Path) -> None:
        session = _FakeSession({"../../etc/passwd.txt": b"escaped"})
        result = await h.harvest_evidence(session=session, run_dir=run_dir)

        for path in result.artifacts:
            assert run_dir in path.parents, f"{path} thoát khỏi run_dir"

    def test_budget_rejects_past_file_limit(self) -> None:
        budget = h._Budget(max_files=2, max_bytes=10_000)
        assert budget.take("a", 1)
        assert budget.take("b", 1)
        assert not budget.take("c", 1)
        assert any("c" in r for r in budget.rejected)


class TestNeverBreaksTheScan:
    @pytest.mark.asyncio
    async def test_session_none_returns_empty(self, run_dir: Path) -> None:
        result = await h.harvest_evidence(session=None, run_dir=run_dir)
        assert result.count == 0

    @pytest.mark.asyncio
    async def test_persist_exception_swallowed(self, run_dir: Path) -> None:
        result = await h.harvest_evidence(session=_FakeSession(boom=True), run_dir=run_dir)
        assert result.count == 0  # không ném ra ngoài

    @pytest.mark.asyncio
    async def test_corrupt_archive_swallowed(self, run_dir: Path) -> None:
        class _Garbage:
            async def persist_workspace(self) -> io.IOBase:
                return io.BytesIO(b"not a tar archive")

        result = await h.harvest_evidence(session=_Garbage(), run_dir=run_dir)
        assert result.count == 0

    @pytest.mark.asyncio
    async def test_workspace_never_read_twice(self, run_dir: Path) -> None:
        session = _FakeSession({"a.txt": b"x"})
        await h.harvest_evidence(session=session, run_dir=run_dir)
        # Một lượt persist là đủ cho cả cây; gọi lại là lãng phí I/O sandbox.
        assert session.persist_calls == 1


class TestSummary:
    def test_summary_is_readable(self) -> None:
        result = h.HarvestedEvidence(
            screenshots=[Path("a.png")], http_exchanges=[], artifacts=[Path("b.xml")]
        )
        result.total_bytes = 2048
        assert "1 ảnh" in result.summary()
        assert "2.0 KB" in result.summary()


class TestDesktopExport:
    def test_exports_when_evidence_exists(self, tmp_path: Path, monkeypatch) -> None:
        run_dir = tmp_path / "run-x"
        (run_dir / "evidence" / "screenshots").mkdir(parents=True)
        (run_dir / "evidence" / "screenshots" / "s.png").write_bytes(b"png")

        desktop = tmp_path / "Desktop"
        desktop.mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        out = runner.export_evidence_to_desktop(run_dir, "run-x")

        assert out is not None
        assert out == desktop / "strix-evidence-run-x"
        assert (out / "screenshots" / "s.png").read_bytes() == b"png"

    def test_no_export_when_evidence_empty(self, tmp_path: Path, monkeypatch) -> None:
        run_dir = tmp_path / "run-y"
        (run_dir / "evidence").mkdir(parents=True)
        desktop = tmp_path / "Desktop"
        desktop.mkdir()
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        assert runner.export_evidence_to_desktop(run_dir, "run-y") is None

    def test_existing_desktop_copy_is_replaced(self, tmp_path: Path, monkeypatch) -> None:
        run_dir = tmp_path / "run-z"
        (run_dir / "evidence").mkdir(parents=True)
        (run_dir / "evidence" / "new.txt").write_text("new", encoding="utf-8")

        desktop = tmp_path / "Desktop"
        stale = desktop / "strix-evidence-run-z"
        stale.mkdir(parents=True)
        (stale / "old.txt").write_text("old", encoding="utf-8")

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        out = runner.export_evidence_to_desktop(run_dir, "run-z")

        assert out is not None
        assert (out / "new.txt").exists()
        assert not (out / "old.txt").exists()
        shutil.rmtree(out, ignore_errors=True)


class _FakeCaidoHandle(CaidoBootstrapHandle):
    """CaidoBootstrapHandle thật, nhưng task giả: chỉ nối handler ``get()``.

    Kế thừa ĐÚNG lớp thật để đi qua nhánh ``isinstance`` trong harvester -
    đúng thứ đã hỏng (handle bị truyền thẳng vào SDK thay vì resolve).
    """

    def __init__(self, client: object, *, boom: bool = False) -> None:
        # Cố ý KHÔNG gọi super().__init__: không có task bootstrap nào ở đây.
        self._client = client
        self._boom = boom
        self.get_calls = 0

    async def get(self) -> object:
        self.get_calls += 1
        if self._boom:
            raise RuntimeError("caido login failed")
        return self._client


class _FakeExchange:
    def __init__(self, raw_request: str, raw_response: str) -> None:
        self.request = SimpleNamespace(raw=raw_request)
        self.response = SimpleNamespace(raw=raw_response)


class TestResolveCaidoClient:
    """Harvester phải resolve handle, không truyền thẳng handle vào SDK.

    Lỗi đo được trước khi vá: mọi lượt quét log
    ``'CaidoBootstrapHandle' object has no attribute 'request'`` và phần HTTP
    luôn ra 0 file, nên ``http_exchange_ids`` trong báo cáo thành vô nghĩa.
    """

    @pytest.mark.asyncio
    async def test_resolves_handle_to_client(self) -> None:
        client = object()
        handle = _FakeCaidoHandle(client)

        assert await h._resolve_caido_client(handle) is client
        assert handle.get_calls == 1

    @pytest.mark.asyncio
    async def test_plain_client_passes_through(self) -> None:
        client = object()
        assert await h._resolve_caido_client(client) is client

    @pytest.mark.asyncio
    async def test_none_stays_none(self) -> None:
        assert await h._resolve_caido_client(None) is None

    @pytest.mark.asyncio
    async def test_failed_bootstrap_degrades_to_none(self) -> None:
        # Bootstrap hỏng chỉ bỏ phần HTTP; thân cuộc quét vẫn phải thu được.
        assert await h._resolve_caido_client(_FakeCaidoHandle(object(), boom=True)) is None


class TestHarvestHttpExchanges:
    @pytest.mark.asyncio
    async def test_handle_is_resolved_and_exchanges_are_written(
        self, run_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exchange = _FakeExchange("GET /hoso/1 HTTP/1.1", "HTTP/1.1 200 OK")
        seen: list[tuple[object, str]] = []

        async def _fake_get(client: object, request_id: str, **_kw: object) -> object:
            seen.append((client, request_id))
            return exchange

        monkeypatch.setattr(caido_api, "get_request_with_client", _fake_get)

        client = object()
        result = await h.harvest_evidence(
            session=_FakeSession({}),
            run_dir=run_dir,
            reports=[{"title": "lộ dữ liệu bệnh án", "http_exchange_ids": ["3410"]}],
            caido_client=_FakeCaidoHandle(client),
        )

        # SDK phải nhận CLIENT, không phải handle.
        assert seen == [(client, "3410")]
        assert len(result.http_exchanges) == 1
        written = (run_dir / "evidence" / "http" / "exchange-3410.txt").read_text(encoding="utf-8")
        assert "lộ dữ liệu bệnh án" in written
        assert "GET /hoso/1 HTTP/1.1" in written
        assert "HTTP/1.1 200 OK" in written

    @pytest.mark.asyncio
    async def test_broken_bootstrap_skips_http_without_failing_scan(self, run_dir: Path) -> None:
        result = await h.harvest_evidence(
            session=_FakeSession({"scan.xml": b"<nmaprun/>"}),
            run_dir=run_dir,
            reports=[{"title": "x", "http_exchange_ids": ["1"]}],
            caido_client=_FakeCaidoHandle(object(), boom=True),
        )

        assert result.http_exchanges == []
        # Phần còn lại của chứng cứ vẫn phải sống sót.
        assert len(result.artifacts) == 1


class TestScreenshotPathsArePreserved:
    """Ảnh trùng tên ở thư mục khác nhau không được ghi đè nhau."""

    @pytest.mark.asyncio
    async def test_same_basename_in_different_dirs_both_survive(self, run_dir: Path) -> None:
        session = _FakeSession(
            {
                ".agent-browser-screenshots/hoichan/shot.png": b"anh-1",
                ".agent-browser-screenshots/pacs/shot.png": b"anh-2",
            }
        )

        result = await h.harvest_evidence(session=session, run_dir=run_dir)

        assert len(result.screenshots) == 2
        saved = {p.read_bytes() for p in result.screenshots}
        assert saved == {b"anh-1", b"anh-2"}

    @pytest.mark.asyncio
    async def test_image_outside_screenshot_dir_keeps_its_tree(self, run_dir: Path) -> None:
        session = _FakeSession({"artifacts/wp/assets/icon.png": b"asset"})

        result = await h.harvest_evidence(session=session, run_dir=run_dir)

        assert len(result.screenshots) == 1
        assert result.screenshots[0] == (
            run_dir / "evidence" / "screenshots" / "artifacts/wp/assets/icon.png"
        )

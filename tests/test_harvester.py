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

import pytest

from strix.core import runner
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
        session = _FakeSession({
            ".agent-browser-screenshots/page1.png": b"\x89PNG-fake-1",
            ".agent-browser-screenshots/page2.png": b"\x89PNG-fake-2",
        })

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
        session = _FakeSession({
            "app.py": b"print('target source')",
            ".agent-browser-screenshots/shot.png": b"png",
        })
        result = await h.harvest_evidence(session=session, run_dir=run_dir)
        assert len(result.screenshots) == 1
        # `app.py` là mã nguồn target, không phải chứng cứ của cuộc kiểm thử.
        assert all("app.py" not in str(p) for p in result.artifacts)


class TestHarvestArtifacts:
    @pytest.mark.asyncio
    async def test_copies_tool_output_and_other_evidence(self, run_dir: Path) -> None:
        session = _FakeSession({
            ".tool-output/out1.txt": b"nmap result",
            "scan.xml": b"<nmaprun/>",
            "junk.bin": b"\x00\x01",
        })

        result = await h.harvest_evidence(session=session, run_dir=run_dir)

        assert len(result.artifacts) == 2
        assert (run_dir / "evidence" / "artifacts" / "scan.xml").read_bytes() == b"<nmaprun/>"
        assert (run_dir / "evidence" / "tool-output" / "out1.txt").read_bytes() == b"nmap result"
        # Đuôi không nằm trong danh sách chứng cứ thì bỏ qua.
        assert not (run_dir / "evidence" / "artifacts" / "junk.bin").exists()

    @pytest.mark.asyncio
    async def test_skips_database_files(self, run_dir: Path) -> None:
        session = _FakeSession({
            "db.sqlite": b"SQLite format 3",
            "keep.json": b"{}",
        })
        result = await h.harvest_evidence(session=session, run_dir=run_dir)
        assert len(result.artifacts) == 1
        assert (run_dir / "evidence" / "artifacts" / "keep.json").exists()

    @pytest.mark.asyncio
    async def test_skips_target_source_directories(self, run_dir: Path) -> None:
        session = _FakeSession({
            "node_modules/pkg/index.js": b"// dep",
            "__pycache__/mod.pyc": b"\x00",
            ".git/config": b"[core]",
            "report.md": b"# real evidence",
        })
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

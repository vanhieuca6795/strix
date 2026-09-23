"""Test cho giới hạn agent con chạy song song (bảo vệ RAM)."""

from __future__ import annotations

import pytest

from strix.config import loader as config_loader
from strix.config.loader import load_settings
from strix.core.execution import _concurrency_limit_error


class _FakeCoordinator:
    """Bắt chước AgentCoordinator chỉ với phần cần thiết."""

    def __init__(self, active: list[str] | None = None) -> None:
        self._active = active or []

    async def active_agents_except(self, *, agent_id: str) -> list[dict[str, str]]:
        del agent_id  # cách dùng thật truyền id agent cần loại trừ
        return [
            {"agent_id": f"id{i}", "name": name, "status": "running"}
            for i, name in enumerate(self._active)
        ]


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> None:
    config_loader._cached = None
    yield
    config_loader._cached = None


class TestDefaultLimit:
    def test_default_is_three(self) -> None:
        assert load_settings().context.max_concurrent_agents == 3

    def test_setting_is_configurable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_MAX_CONCURRENT_AGENTS", "5")
        config_loader._cached = None
        assert load_settings().context.max_concurrent_agents == 5


class TestSpawnAllowed:
    @pytest.mark.asyncio
    async def test_below_limit_allows_spawn(self) -> None:
        result = await _concurrency_limit_error(_FakeCoordinator(["A", "B"]), "New")
        assert result is None

    @pytest.mark.asyncio
    async def test_no_agents_allows_spawn(self) -> None:
        assert await _concurrency_limit_error(_FakeCoordinator([]), "New") is None


class TestSpawnBlocked:
    @pytest.mark.asyncio
    async def test_at_limit_blocks_spawn(self) -> None:
        result = await _concurrency_limit_error(
            _FakeCoordinator(["A", "B", "C"]), "Fourth Agent"
        )
        assert result is not None
        assert result["success"] is False
        assert "Concurrency limit reached" in result["error"]
        assert "Fourth Agent" in result["error"]

    @pytest.mark.asyncio
    async def test_over_limit_blocks_spawn(self) -> None:
        result = await _concurrency_limit_error(_FakeCoordinator(["A", "B", "C", "D"]), "Fifth")
        assert result is not None

    @pytest.mark.asyncio
    async def test_error_names_running_agents(self) -> None:
        result = await _concurrency_limit_error(
            _FakeCoordinator(["Recon", "Exploit", "Injection"]), "New"
        )
        assert result is not None
        assert "Recon" in result["running_agents"]
        assert "Exploit" in result["running_agents"]

    @pytest.mark.asyncio
    async def test_error_is_actionable(self) -> None:
        result = await _concurrency_limit_error(_FakeCoordinator(["A", "B", "C"]), "New")
        assert result is not None
        # Lỗi phải cho model biết cách xử lý, không chỉ báo thất bại.
        assert "wait_for_agents" in result["hint"]
        assert "STRIX_MAX_CONCURRENT_AGENTS" in result["hint"]
        assert result["limit"] == 3


class TestLimitDisabled:
    @pytest.mark.asyncio
    async def test_zero_limit_disables_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_MAX_CONCURRENT_AGENTS", "0")
        config_loader._cached = None

        result = await _concurrency_limit_error(
            _FakeCoordinator(["A", "B", "C", "D", "E", "F"]), "Many"
        )
        assert result is None, "Đặt 0 nghĩa là không giới hạn"

    @pytest.mark.asyncio
    async def test_higher_limit_allows_more(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("STRIX_MAX_CONCURRENT_AGENTS", "10")
        config_loader._cached = None

        assert await _concurrency_limit_error(_FakeCoordinator(["A"] * 8), "New") is None


class TestConfigFailureIsNonBlocking:
    @pytest.mark.asyncio
    async def test_config_error_does_not_block_spawn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Lỗi đọc cấu hình không được biến thành chặn spawn — đó là hành vi tệ hơn.
        def _boom() -> None:
            raise RuntimeError("config broken")

        monkeypatch.setattr(config_loader, "load_settings", _boom)
        result = await _concurrency_limit_error(_FakeCoordinator(["A", "B", "C"]), "New")
        assert result is None

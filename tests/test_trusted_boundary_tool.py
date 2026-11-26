"""Tests for the executable trusted-boundary build gate."""

from pathlib import Path

import pytest

from cephas_logisticsos.security import trusted_boundary
from cephas_logisticsos.security.trusted_boundary import main


def _make_package_root(source_root: Path) -> Path:
    package_root = source_root / "cephas_logisticsos"
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text(
        '"""Test production package."""\n',
        encoding="utf-8",
    )
    return package_root


def test_cli_passes_for_safe_production_source_tree(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    (package_root / "handler.py").write_text(
        "def handler():\n    return None\n",
        encoding="utf-8",
    )
    assert main(["--source", str(tmp_path)]) == 0


def test_cli_fails_for_unapproved_trusted_adapter_construction(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    (package_root / "handler.py").write_text(
        "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
        "adapter = TrustedTenantContextAdapter(auth, memberships)\n",
        encoding="utf-8",
    )
    assert main(["--source", str(tmp_path)]) == 1


def test_cli_rejects_symlinked_package_directory_with_trusted_call(
    tmp_path: Path,
) -> None:
    package_root = _make_package_root(tmp_path)
    hidden_package = tmp_path.parent / f"{tmp_path.name}-hidden-package"
    hidden_package.mkdir()
    (hidden_package / "__init__.py").write_text("", encoding="utf-8")
    (hidden_package / "rogue.py").write_text(
        "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
        "adapter = TrustedTenantContextAdapter(auth, memberships)\n",
        encoding="utf-8",
    )
    (package_root / "hidden_package").symlink_to(hidden_package, target_is_directory=True)

    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_rejects_symlinked_python_file(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    hidden_file = tmp_path.parent / f"{tmp_path.name}-hidden.py"
    hidden_file.write_text("value = 1\n", encoding="utf-8")
    (package_root / "hidden.py").symlink_to(hidden_file)

    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


@pytest.mark.parametrize("layout", ["empty", "unrelated"])
def test_cli_rejects_missing_expected_package_root(tmp_path: Path, layout: str) -> None:
    if layout == "unrelated":
        unrelated = tmp_path / "another_package"
        unrelated.mkdir()
        (unrelated / "__init__.py").write_text("", encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_rejects_package_without_initializer(tmp_path: Path) -> None:
    (tmp_path / "cephas_logisticsos").mkdir()
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_rejects_missing_source_root(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path / "missing")])
    assert error.value.code == 2


def test_cli_reports_syntax_errors_as_scan_failures(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    (package_root / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_fails_closed_on_filesystem_walk_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_package_root(tmp_path)

    def fail_walk(*args: object, **kwargs: object) -> None:
        raise PermissionError("simulated inaccessible source directory")

    monkeypatch.setattr(trusted_boundary.os, "walk", fail_walk)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_fails_closed_on_unexpected_scanner_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_scan(source_root: Path) -> list[str]:
        raise RuntimeError("simulated scanner failure")

    monkeypatch.setattr(trusted_boundary, "scan_source_tree", fail_scan)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_rejects_symlinked_source_root(tmp_path: Path) -> None:
    real_root = tmp_path / "real-source"
    real_root.mkdir()
    package_root = _make_package_root(real_root)
    (package_root / "handler.py").write_text("value = 1\\n", encoding="utf-8")
    linked_root = tmp_path / "source-link"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(linked_root)])
    assert error.value.code == 2


def test_cli_rejects_symlinked_package_root(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    external_package = tmp_path.parent / f"{tmp_path.name}-external-package"
    package_root.rename(external_package)
    (tmp_path / "cephas_logisticsos").symlink_to(external_package, target_is_directory=True)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_rejects_symlinked_package_initializer(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    external_initializer = tmp_path.parent / f"{tmp_path.name}-external-init.py"
    external_initializer.write_text('"""External initializer."""\\n', encoding="utf-8")
    (package_root / "__init__.py").unlink()
    (package_root / "__init__.py").symlink_to(external_initializer)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_rejects_symlink_cycle(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    (package_root / "cycle").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_rejects_source_root_reached_through_symlinked_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    source_root = real_parent / "src"
    source_root.mkdir(parents=True)
    package_root = _make_package_root(source_root)
    (package_root / "handler.py").write_text("value = 1\\n", encoding="utf-8")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(linked_parent / "src")])
    assert error.value.code == 2


def test_cli_fails_closed_on_invalid_utf8_source(tmp_path: Path) -> None:
    package_root = _make_package_root(tmp_path)
    (package_root / "invalid.py").write_bytes(b"value = \\xff\\n")
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2


def test_cli_fails_closed_on_file_read_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = _make_package_root(tmp_path)
    target = package_root / "unreadable.py"
    target.write_text("value = 1\\n", encoding="utf-8")
    original_read_text = Path.read_text

    def fail_target_read(path: Path, *args: object, **kwargs: object) -> str:
        if path == target:
            raise PermissionError("simulated source file read failure")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_target_read)
    with pytest.raises(SystemExit) as error:
        main(["--source", str(tmp_path)])
    assert error.value.code == 2

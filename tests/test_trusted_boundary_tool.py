"""Tests for the executable trusted-boundary build gate."""

from pathlib import Path

from cephas_logisticsos.security.trusted_boundary import main


def test_cli_passes_for_safe_source_tree(tmp_path: Path) -> None:
    source = tmp_path / "safe_module.py"
    source.write_text("def handler():\n    return None\n", encoding="utf-8")
    assert main(["--source", str(tmp_path)]) == 0


def test_cli_fails_for_unapproved_trusted_adapter_construction(tmp_path: Path) -> None:
    source = tmp_path / "handler.py"
    source.write_text(
        "from cephas_logisticsos.tenancy.trusted_context import TrustedTenantContextAdapter\n"
        "adapter = TrustedTenantContextAdapter(auth, memberships)\n",
        encoding="utf-8",
    )
    assert main(["--source", str(tmp_path)]) == 1

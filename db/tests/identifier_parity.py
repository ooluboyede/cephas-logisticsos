"""Compare actual PostgreSQL domain casts with the production Python identifier validator."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Iterable

from cephas_logisticsos.core.identifiers import validate_identifier


def vectors() -> Iterable[str]:
    yield from ("", "a", "Z", "0", "a._:-9", "a" * 128, "a" * 129)
    yield from ("-a", ".a", "_a", ":a", " a", "a ", "a\n", "a\r", "a\t", "a b")
    yield from ("é", "aé", "a😀", "Ａ", "a\u00a0", "a/", "a'", 'a"', "a\\", "a;")
    # Every non-NUL ASCII code point, both at the initial and subsequent position.
    for codepoint in range(1, 128):
        char = chr(codepoint)
        yield char + "a"
        yield "a" + char


def python_accepts(value: str) -> bool:
    try:
        return validate_identifier(value, field_name="test") == value
    except ValueError:
        return False


def main() -> None:
    container = os.environ["PG16_CONTAINER_ID"]
    if re.fullmatch(r"[a-f0-9]{12,64}", container) is None:
        raise RuntimeError("invalid disposable service container")
    values = list(dict.fromkeys(vectors()))
    # Hex encodes all input bytes: no interpolated raw SQL text.
    rows = ",\n".join(f"({i},'{v.encode('utf-8').hex()}')" for i, v in enumerate(values))
    script = f"""
BEGIN;
SET LOCAL search_path=pg_catalog;
DO $guard$
BEGIN
    IF current_database()<>'cephas_t02_test'
        OR current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
    THEN RAISE EXCEPTION 'wrong test environment'; END IF;
END
$guard$;
CREATE FUNCTION pg_temp.accept_identifier(value text) RETURNS boolean
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM value::security.identifier;
    RETURN true;
EXCEPTION WHEN check_violation THEN
    RETURN false;
END
$fn$;
SELECT id,pg_temp.accept_identifier(convert_from(decode(hex,'hex'),'UTF8'))
FROM (VALUES
{rows}
) AS vectors(id,hex) ORDER BY id;
ROLLBACK;
"""
    # Fixed executable and parameters, validated container ID; no shell.
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("docker unavailable")
    result = subprocess.run(  # noqa: S603
        [
            docker,
            "exec",
            "-i",
            container,
            "psql",
            "-X",
            "-w",
            "-U",
            "postgres",
            "-d",
            "cephas_t02_test",
            "-v",
            "ON_ERROR_STOP=1",
            "-Atq",
        ],
        input=script,
        text=True,
        capture_output=True,
        check=True,
        timeout=60,
    )
    expected = [f"{i}|{'t' if python_accepts(v) else 'f'}" for i, v in enumerate(values)]
    if result.stdout.splitlines() != expected:
        raise RuntimeError("Python/PostgreSQL identifier equivalence mismatch")
    print(f"Python/PostgreSQL identifier parity passed: {len(values)} text vectors")


if __name__ == "__main__":
    main()

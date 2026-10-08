from pathlib import Path

import pytest


@pytest.fixture
def fixtures() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def fake_runner(fixtures):
    """Build a runner returning canned (rc, stdout, stderr) per command prefix."""

    def make(responses: dict[str, tuple[int, str]]):
        calls: list[list[str]] = []

        def runner(argv):
            calls.append(list(argv))
            key = " ".join(argv)
            for prefix, (rc, name) in responses.items():
                if key.startswith(prefix):
                    if name is None:
                        raise FileNotFoundError(argv[0])
                    text = (fixtures / name).read_text() if name else ""
                    return rc, text, ""
            raise FileNotFoundError(argv[0])

        runner.calls = calls
        return runner

    return make

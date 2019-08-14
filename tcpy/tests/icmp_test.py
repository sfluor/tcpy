from .utils import run_cmd_with_stack


def test_arping() -> None:
    # Calling ping
    run_cmd_with_stack(["ping", "-c3", "10.0.0.4"])

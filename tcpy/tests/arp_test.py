from .utils import run_cmd_with_stack


def test_arping() -> None:
    # Calling arping
    run_cmd_with_stack(["arping", "-c3", "-I", "tap0", "10.0.0.4"])

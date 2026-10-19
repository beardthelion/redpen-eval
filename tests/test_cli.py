import pytest

from redpen.cli import main


def run(argv):
    try:
        return main(argv)
    except SystemExit as exc:
        return exc.code


def test_help_lists_subcommands(capsys):
    assert run(["--help"]) == 0
    out = capsys.readouterr().out
    for name in ("build-dataset", "run", "report"):
        assert name in out


def test_unknown_subcommand_exits_2():
    assert run(["frobnicate"]) == 2


def test_no_subcommand_prints_help_and_returns_2(capsys):
    assert run([]) == 2
    captured = capsys.readouterr()
    assert "build-dataset" in captured.out + captured.err


@pytest.mark.parametrize("command", ["build-dataset", "run", "report"])
def test_stub_commands_return_2(command, capsys):
    assert run([command]) == 2
    assert f"redpen: {command} is not implemented yet" in capsys.readouterr().err

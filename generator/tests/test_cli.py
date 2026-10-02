import json

from click.testing import CliRunner

from cli import cli


def test_generate_writes_ndjson_to_file(tmp_path):
    output = tmp_path / "events.ndjson"
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "--events", "10", "--seed", "1", "--output", str(output)])
    assert result.exit_code == 0, result.output
    lines = output.read_text().strip().splitlines()
    assert len(lines) == 10
    first = json.loads(lines[0])
    assert first["event_id"].startswith("evt-")


def test_generate_unknown_scenario_fails_clearly():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "--events", "5", "--scenario", "not-a-real-scenario"])
    assert result.exit_code != 0


def test_list_scenarios_includes_normal_traffic():
    runner = CliRunner()
    result = runner.invoke(cli, ["list-scenarios"])
    assert result.exit_code == 0
    assert "normal-traffic" in result.output


def test_generate_rate_and_duration_computes_count(tmp_path):
    output = tmp_path / "events.ndjson"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "generate", "--rate", "10", "--duration", "5", "--seed", "1", "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    lines = output.read_text().strip().splitlines()
    assert len(lines) == 50  # 10 events/sec * 5s


def test_generate_rate_without_duration_is_a_usage_error():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "--rate", "10"])
    assert result.exit_code != 0
    assert "requires --duration" in result.output


def test_generate_attack_ratio_blends_scenarios(tmp_path):
    output = tmp_path / "events.ndjson"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "generate", "--events", "20", "--scenario", "brute-force",
        "--attack-ratio", "0.5", "--seed", "1", "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    lines = [json.loads(l) for l in output.read_text().strip().splitlines()]
    scenarios_seen = {l["metadata"]["scenario"] for l in lines}
    assert scenarios_seen == {"brute-force", "normal-traffic"}


def test_generate_events_takes_priority_over_rate_and_duration(tmp_path):
    output = tmp_path / "events.ndjson"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "generate", "--events", "7", "--rate", "100", "--duration", "100",
        "--seed", "1", "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    assert len(output.read_text().strip().splitlines()) == 7


def test_produce_reports_failure_when_broker_unreachable():
    """Real produce path, real confluent_kafka.Producer, closed port - bounded and fast."""
    # mix_stderr=False so stdout and stderr are checked as the separate
    # streams they actually are - the default CliRunner merges them into
    # one `result.output`, which made this look like a stdout-corruption
    # bug on first pass until checked with real OS-level file descriptors
    # (see docs/phases.md).
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, [
        "produce", "--events", "3", "--bootstrap-servers", "127.0.0.1:1",
        "--delivery-timeout-ms", "500", "--flush-timeout", "2", "--seed", "1",
    ])
    assert result.exit_code == 1
    summary = json.loads(result.stdout.strip())
    assert summary["queued"] == 3
    assert summary["failed"] == 3
    assert summary["delivered"] == 0


def test_produce_stdout_contains_only_the_json_summary_line():
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, [
        "produce", "--events", "2", "--bootstrap-servers", "127.0.0.1:1",
        "--delivery-timeout-ms", "300", "--flush-timeout", "1", "--seed", "1",
    ])
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 1
    json.loads(lines[0])  # must parse as exactly one JSON object
    # And confirm stderr is non-empty (logs really did go somewhere).
    assert len(result.stderr.strip()) > 0


def test_generate_help_documents_key_options():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate", "--help"])
    assert result.exit_code == 0
    for option in ["--events", "--rate", "--duration", "--scenario", "--attack-ratio", "--output"]:
        assert option in result.output


def test_produce_help_documents_key_options():
    runner = CliRunner()
    result = runner.invoke(cli, ["produce", "--help"])
    assert result.exit_code == 0
    for option in ["--bootstrap-servers", "--acks", "--compression", "--client-id"]:
        assert option in result.output

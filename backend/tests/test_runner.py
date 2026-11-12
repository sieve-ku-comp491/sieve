"""The plug-in runner with a fake container engine, so these tests need no Docker."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from app.runner import (
    BuildStep,
    ContainerResult,
    ContainerSpec,
    EngineError,
    InMemoryRunStore,
    Mount,
    PluginManifest,
    PluginRun,
    PluginRunner,
    Reason,
    RunLog,
    RunnerSettings,
    RunStatus,
    SarifValidator,
    ScanTarget,
    maven_cache_volume,
    run_plugins,
    scan_status,
)

SCAN = ScanTarget(scan_id="scan-1", repo_url="https://github.com/example/app")

VALID_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "fake", "semanticVersion": "9.9.9"}},
            "results": [
                {"ruleId": "r1", "message": {"text": "one"}},
                {"ruleId": "r2", "message": {"text": "two"}},
            ],
        }
    ],
}

Output = Callable[[Path], None]


def write_output(sarif: object = VALID_SARIF, files_scanned: object = 3) -> Output:
    def write(out_dir: Path) -> None:
        if sarif is not None:
            text = sarif if isinstance(sarif, str) else json.dumps(sarif)
            (out_dir / "results.sarif").write_text(text, encoding="utf-8")
        if files_scanned is not None:
            info = {"files_scanned": files_scanned}
            (out_dir / "scan-info.json").write_text(json.dumps(info), encoding="utf-8")

    return write


class FakeEngine:
    """Hands out results in order. A result can come with output that the plug-in "writes"."""

    def __init__(self, *steps: tuple[ContainerResult, Output | None] | ContainerResult):
        self.steps = list(steps)
        self.specs: list[ContainerSpec] = []
        self.timeouts: list[float] = []
        self.missing_images: set[str] = set()
        self.removed: list[tuple[str, str]] = []
        self.open_networks: set[str] = set()
        self.on_run: Callable[[], None] | None = None

    def image_digest(self, image: str) -> str:
        if image in self.missing_images:
            raise EngineError(f"the image {image} is not on this machine")
        return f"sha256:{image}"

    def run(self, spec: ContainerSpec, timeout_seconds: float) -> ContainerResult:
        self.specs.append(spec)
        self.timeouts.append(timeout_seconds)
        if self.on_run:
            self.on_run()
        step = self.steps.pop(0)
        result, output = step if isinstance(step, tuple) else (step, None)
        if output:
            out = next(m for m in spec.mounts if m.target == "/out")
            output(Path(out.host_path))
        return result

    def remove_labeled(self, label: str, value: str) -> None:
        self.removed.append((label, value))

    def network_is_internal(self, name: str) -> bool:
        return name not in self.open_networks


def plugin(**changes) -> PluginManifest:
    fields = {
        "name": "fake",
        "image": "sieve-plugin-fake:1.0-abc",
        "languages": ("python",),
        "adapter": "fake",
        "tool_version": "1.0",
        "rules_version": "rules@abc",
        "timeout_seconds": 600,
    }
    return PluginManifest(**(fields | changes))


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    checkout = tmp_path / "scans" / SCAN.scan_id / "src"
    (checkout / "pkg").mkdir(parents=True)
    (checkout / "app.py").write_text("print('hi')\n")
    (checkout / "pkg" / "util.py").write_text("x = 1\n")
    (checkout / "README.md").write_text("readme\n")
    return tmp_path


def make_runner(data_dir: Path, engine: FakeEngine, **settings) -> PluginRunner:
    settings = {"data_dir": data_dir, "data_volume": None} | settings
    return PluginRunner(engine, InMemoryRunStore(), RunnerSettings(**settings))


def run_one(runner: PluginRunner, manifest: PluginManifest) -> PluginRun:
    run = runner.store.create_run(SCAN.scan_id, manifest)
    return runner.run(SCAN, manifest, run)


def log_text(data_dir: Path, run: PluginRun) -> str:
    return (data_dir / run.log_path).read_text(encoding="utf-8")


def ok() -> tuple[ContainerResult, Output]:
    return ContainerResult(exit_code=0, log="scanning\n"), write_output()


# The flags every container gets


def test_scan_container_gets_the_contract_flags(data_dir):
    engine = FakeEngine(ok())
    run = run_one(make_runner(data_dir, engine), plugin())

    [spec] = engine.specs
    assert spec.image == "sieve-plugin-fake:1.0-abc"
    assert spec.network == "none"
    assert spec.user == "10001:10001"
    assert spec.read_only is True
    assert spec.tmpfs == ("/tmp",)
    assert spec.cap_drop == ("ALL",)
    assert spec.no_new_privileges is True
    assert (spec.memory, spec.cpus, spec.pids_limit) == ("4g", 2.0, 512)
    assert spec.env == {"SIEVE_SRC": "/src", "SIEVE_OUT": "/out", "HOME": "/tmp"}
    assert spec.labels == {
        "sieve.scan_id": "scan-1",
        "sieve.run_id": run.run_id,
        "sieve.step": "scan",
    }
    mounts = {m.target: m for m in spec.mounts}
    assert set(mounts) == {"/src", "/out"}
    assert mounts["/src"].read_only and not mounts["/out"].read_only
    assert Path(mounts["/src"].host_path) == (data_dir / "scans/scan-1/src").resolve()
    assert Path(mounts["/out"].host_path) == (data_dir / f"runs/{run.run_id}/out").resolve()


def test_containers_get_subpaths_of_the_data_volume(data_dir):
    engine = FakeEngine(ok())
    runner = make_runner(data_dir, engine, data_volume="sieve-data")
    run = runner.store.create_run(SCAN.scan_id, plugin())
    engine.steps = [ContainerResult(exit_code=0)]
    runner.run(SCAN, plugin(), run)

    mounts = {m.target: m for m in engine.specs[0].mounts}
    assert mounts["/src"] == Mount(
        target="/src", read_only=True, volume="sieve-data", subpath="scans/scan-1/src"
    )
    assert mounts["/out"] == Mount(
        target="/out", read_only=False, volume="sieve-data", subpath=f"runs/{run.run_id}/out"
    )


def test_settings_from_env():
    settings = RunnerSettings.from_env(
        {"SIEVE_DATA_DIR": "/srv/data", "SIEVE_DATA_VOLUME": "", "SIEVE_BUILD_NETWORK": "b"}
    )
    assert settings.data_dir == Path("/srv/data")
    assert settings.data_volume is None
    assert settings.build_network == "b"
    assert RunnerSettings.from_env({}).data_volume == "sieve-data"


# Run statuses


def test_success_records_versions_counts_and_paths(data_dir):
    engine = FakeEngine(ok())
    runner = make_runner(data_dir, engine)
    run = run_one(runner, plugin())

    assert run.status is RunStatus.SUCCEEDED
    assert run.reason is None
    assert run.exit_code == 0
    assert (run.files_scanned, run.result_count) == (3, 2)
    assert (run.tool_version, run.rules_version) == ("1.0", "rules@abc")
    assert run.image_digest == "sha256:sieve-plugin-fake:1.0-abc"
    assert run.sarif_path == f"runs/{run.run_id}/out/results.sarif"
    assert run.log_path == f"runs/{run.run_id}/log"
    assert run.started_at <= run.finished_at
    statuses = [status for run_id, status in runner.store.history if run_id == run.run_id]
    assert statuses == [RunStatus.PENDING, RunStatus.RUNNING, RunStatus.SUCCEEDED]

    log = log_text(data_dir, run)
    assert "tool 1.0, rules rules@abc" in log
    assert "image digest sha256:sieve-plugin-fake:1.0-abc" in log
    assert "the SARIF file names fake 9.9.9, the manifest says 1.0" in log
    assert "scanning" in log


@pytest.mark.parametrize(
    ("output", "reason"),
    [
        (write_output(sarif=None), Reason.MISSING_SARIF),
        (write_output(files_scanned=None), Reason.MISSING_SARIF),
        (write_output(files_scanned="many"), Reason.MISSING_SARIF),
        (write_output(sarif="not json {"), Reason.INVALID_SARIF),
        (write_output(sarif={"version": "2.0.0", "runs": []}), Reason.INVALID_SARIF),
        (write_output(sarif={"version": "2.1.0", "runs": [{"results": []}]}), Reason.INVALID_SARIF),
        (write_output(sarif=[1, 2]), Reason.INVALID_SARIF),
    ],
    ids=["no sarif", "no scan-info", "bad scan-info", "not json", "old version", "schema", "list"],
)
def test_bad_output_fails_the_run(data_dir, output, reason):
    engine = FakeEngine((ContainerResult(exit_code=0), output))
    run = run_one(make_runner(data_dir, engine), plugin())

    assert (run.status, run.reason) == (RunStatus.FAILED, reason)
    assert run.sarif_path is None
    assert reason.value in log_text(data_dir, run)


@pytest.mark.parametrize("name", ["results.sarif", "scan-info.json"])
def test_output_files_that_are_links_are_refused(data_dir, tmp_path_factory, name):
    secret = tmp_path_factory.mktemp("outside") / "environ"
    secret.write_text(json.dumps(VALID_SARIF if name == "results.sarif" else {"files_scanned": 3}))

    def link_output(out_dir: Path) -> None:
        write_output()(out_dir)
        (out_dir / name).unlink()
        try:
            (out_dir / name).symlink_to(secret)
        except OSError:
            pytest.skip("this machine doesn't allow symbolic links")

    engine = FakeEngine((ContainerResult(exit_code=0), link_output))
    run = run_one(make_runner(data_dir, engine), plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.INVALID_SARIF)
    assert "is not a regular file" in log_text(data_dir, run)


def test_sarif_over_the_size_limit_is_invalid(data_dir):
    engine = FakeEngine(ok())
    runner = make_runner(data_dir, engine)
    runner.validator = SarifValidator(max_bytes=50)
    run = run_one(runner, plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.INVALID_SARIF)


def test_crash_fails_with_exit_code_and_keeps_the_log(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=2, log="crashing on purpose\n"))
    run = run_one(make_runner(data_dir, engine), plugin())

    assert (run.status, run.reason, run.exit_code) == (RunStatus.FAILED, Reason.EXIT_CODE, 2)
    assert "crashing on purpose" in log_text(data_dir, run)


def test_zero_files_scanned_is_a_failure_when_the_checkout_has_such_files(data_dir):
    engine = FakeEngine((ContainerResult(exit_code=0), write_output(files_scanned=0)))
    run = run_one(make_runner(data_dir, engine), plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.NOTHING_SCANNED)


def test_zero_files_scanned_is_fine_when_the_checkout_has_none(data_dir):
    engine = FakeEngine((ContainerResult(exit_code=0), write_output(files_scanned=0)))
    run = run_one(make_runner(data_dir, engine), plugin(languages=("java",)))
    assert run.status is RunStatus.SUCCEEDED


def test_exit_3_is_skipped_when_the_checkout_has_no_files_in_the_languages(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=3))
    run = run_one(make_runner(data_dir, engine), plugin(languages=("java",)))
    assert (run.status, run.reason) == (RunStatus.SKIPPED, None)


def test_exit_3_fails_when_the_checkout_has_files_in_the_languages(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=3))
    run = run_one(make_runner(data_dir, engine), plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.NOTHING_SCANNED)


def test_exit_3_fails_for_a_plugin_that_scans_every_file(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=3))
    run = run_one(make_runner(data_dir, engine), plugin(languages=("*",)))
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.NOTHING_SCANNED)


def test_timeout(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=None, timed_out=True, log="sleeping\n"))
    run = run_one(make_runner(data_dir, engine), plugin(timeout_seconds=30))

    assert (run.status, run.reason, run.exit_code) == (RunStatus.TIMED_OUT, None, None)
    assert engine.timeouts == [pytest.approx(30, abs=1)]
    assert "reached the time limit" in log_text(data_dir, run)


def test_out_of_memory(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=137, out_of_memory=True))
    run = run_one(make_runner(data_dir, engine), plugin())
    assert (run.status, run.reason, run.exit_code) == (
        RunStatus.FAILED,
        Reason.OUT_OF_MEMORY,
        137,
    )


def test_container_that_cannot_start_is_a_runner_error(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=None, start_failed=True, log="no such mount"))
    run = run_one(make_runner(data_dir, engine), plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert "no such mount" in log_text(data_dir, run)


def test_missing_image_is_a_runner_error_and_starts_nothing(data_dir):
    engine = FakeEngine()
    engine.missing_images.add("sieve-plugin-fake:1.0-abc")
    run = run_one(make_runner(data_dir, engine), plugin())

    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert run.image_digest is None
    assert engine.specs == []
    assert "is not on this machine" in log_text(data_dir, run)


def test_missing_checkout_is_a_runner_error(data_dir):
    engine = FakeEngine()
    runner = make_runner(data_dir, engine)
    manifest = plugin()
    run = runner.store.create_run("other-scan", manifest)
    run = runner.run(ScanTarget("other-scan", SCAN.repo_url), manifest, run)
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert engine.specs == []


def test_an_engine_error_ends_the_run_instead_of_raising(data_dir):
    engine = FakeEngine(ok())

    def lose_connection() -> None:
        raise EngineError("lost the connection to the Docker Engine")

    engine.on_run = lose_connection
    run = run_one(make_runner(data_dir, engine), plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert "lost the connection" in log_text(data_dir, run)


def test_old_output_is_removed_before_the_run(data_dir):
    engine = FakeEngine((ContainerResult(exit_code=0), None))
    runner = make_runner(data_dir, engine)
    manifest = plugin()
    run = runner.store.create_run(SCAN.scan_id, manifest)
    write_output()(_make(data_dir / "runs" / run.run_id / "out"))

    run = runner.run(SCAN, manifest, run)
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.MISSING_SARIF)


# Build step


def java_plugin(**changes) -> PluginManifest:
    return plugin(
        name="javaish",
        image="sieve-plugin-javaish:1.0",
        build=BuildStep(image="sieve-plugin-javaish-build:1.0"),
        timeout_seconds=1800,
        **changes,
    )


def test_build_step_runs_first_with_its_own_flags(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=0, log="build done\n"), ok())
    runner = make_runner(data_dir, engine)
    run = run_one(runner, java_plugin())

    assert run.status is RunStatus.SUCCEEDED
    build, scan = engine.specs
    assert build.image == "sieve-plugin-javaish-build:1.0"
    assert build.network == "sieve-build"
    assert build.user == "10001:10001"
    assert build.read_only and build.cap_drop == ("ALL",) and build.no_new_privileges
    assert build.pids_limit == 1024
    assert build.env == {"SIEVE_SRC": "/src", "SIEVE_BUILD": "/build", "HOME": "/tmp"}
    assert build.labels["sieve.step"] == "build"
    build_mounts = {m.target: m for m in build.mounts}
    assert build_mounts["/src"].read_only
    assert not build_mounts["/build"].read_only
    assert build_mounts["/cache/m2"] == Mount(
        target="/cache/m2", read_only=False, volume=maven_cache_volume(SCAN.repo_url)
    )

    assert scan.network == "none"
    scan_mounts = {m.target: m for m in scan.mounts}
    assert set(scan_mounts) == {"/src", "/out", "/build"}
    assert scan_mounts["/build"].read_only
    assert scan_mounts["/build"].host_path == build_mounts["/build"].host_path

    statuses = [status for run_id, status in runner.store.history if run_id == run.run_id]
    assert statuses == [
        RunStatus.PENDING,
        RunStatus.BUILDING,
        RunStatus.RUNNING,
        RunStatus.SUCCEEDED,
    ]
    log = log_text(data_dir, run)
    assert "build image digest sha256:sieve-plugin-javaish-build:1.0" in log
    assert log.index("--- build step") < log.index("build done") < log.index("--- scan step")


def test_failed_build_stops_before_the_scan(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=1, log="the build broke\n"))
    run = run_one(make_runner(data_dir, engine), java_plugin())

    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.BUILD_FAILED)
    assert len(engine.specs) == 1
    assert "the build broke" in log_text(data_dir, run)


def test_build_timeout_stops_before_the_scan(data_dir):
    engine = FakeEngine(ContainerResult(exit_code=None, timed_out=True))
    run = run_one(make_runner(data_dir, engine), java_plugin())
    assert run.status is RunStatus.TIMED_OUT
    assert len(engine.specs) == 1


def test_build_network_with_a_route_out_is_refused(data_dir):
    engine = FakeEngine()
    engine.open_networks.add("sieve-build")
    run = run_one(make_runner(data_dir, engine), java_plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert engine.specs == []
    assert "not an internal bridge network" in log_text(data_dir, run)


def test_missing_build_image_is_a_runner_error(data_dir):
    engine = FakeEngine()
    engine.missing_images.add("sieve-plugin-javaish-build:1.0")
    run = run_one(make_runner(data_dir, engine), java_plugin())
    assert (run.status, run.reason) == (RunStatus.FAILED, Reason.RUNNER_ERROR)
    assert engine.specs == []


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_build_and_scan_share_one_time_limit(data_dir):
    clock = FakeClock()
    engine = FakeEngine(ContainerResult(exit_code=0), ok())

    def build_takes_1700_seconds() -> None:
        if len(engine.specs) == 1:
            clock.now += 1700

    engine.on_run = build_takes_1700_seconds
    runner = make_runner(data_dir, engine)
    runner._clock = clock
    run = run_one(runner, java_plugin())

    assert run.status is RunStatus.SUCCEEDED
    assert engine.timeouts == [1800, 100]


def test_no_time_left_after_the_build_is_a_timeout(data_dir):
    clock = FakeClock()
    engine = FakeEngine(ContainerResult(exit_code=0))

    def build_takes_all_the_time() -> None:
        clock.now += 1800

    engine.on_run = build_takes_all_the_time
    runner = make_runner(data_dir, engine)
    runner._clock = clock
    run = run_one(runner, java_plugin())

    assert run.status is RunStatus.TIMED_OUT
    assert len(engine.specs) == 1


def test_maven_cache_volume_is_per_repository():
    volume = maven_cache_volume("https://github.com/example/app")
    assert volume.startswith("m2-") and len(volume) == 19
    for same in (
        "https://GitHub.com/example/app",
        "https://github.com/example/app/",
        "https://github.com/example/app.git",
    ):
        assert maven_cache_volume(same) == volume
    assert maven_cache_volume("https://github.com/example/other") != volume


# A scan's runs


def test_one_failing_plugin_does_not_stop_the_others(data_dir):
    engine = FakeEngine(
        ContainerResult(exit_code=2, log="crash\n"),
        (ContainerResult(exit_code=0), write_output(sarif="not json")),
        ok(),
    )
    runner = make_runner(data_dir, engine)
    plugins = [plugin(name="crashes"), plugin(name="writes-junk"), plugin(name="works")]
    runs = run_plugins(runner, SCAN, plugins)

    assert [(r.plugin, r.status, r.reason) for r in runs] == [
        ("crashes", RunStatus.FAILED, Reason.EXIT_CODE),
        ("writes-junk", RunStatus.FAILED, Reason.INVALID_SARIF),
        ("works", RunStatus.SUCCEEDED, None),
    ]
    assert len({r.run_id for r in runs}) == 3
    for run in runs:
        assert (data_dir / run.log_path).is_file()
    assert scan_status(runs) == "partial"


def status_run(status: RunStatus) -> PluginRun:
    return PluginRun("r", "s", "p", "i", "t", "r", status=status)


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([RunStatus.SUCCEEDED, RunStatus.SUCCEEDED], "completed"),
        ([RunStatus.SUCCEEDED, RunStatus.SKIPPED], "completed"),
        ([RunStatus.SKIPPED, RunStatus.SKIPPED], "completed"),
        ([], "completed"),
        ([RunStatus.SUCCEEDED, RunStatus.FAILED], "partial"),
        ([RunStatus.SUCCEEDED, RunStatus.TIMED_OUT], "partial"),
        ([RunStatus.FAILED, RunStatus.SKIPPED], "failed"),
        ([RunStatus.TIMED_OUT, RunStatus.FAILED], "failed"),
    ],
)
def test_scan_status(statuses, expected):
    assert scan_status([status_run(s) for s in statuses]) == expected


def test_scan_status_needs_every_run_to_have_ended():
    with pytest.raises(ValueError):
        scan_status([status_run(RunStatus.RUNNING)])


def test_remove_leftovers_removes_the_scans_containers(data_dir):
    engine = FakeEngine()
    make_runner(data_dir, engine).remove_leftovers("scan-1")
    assert engine.removed == [("sieve.scan_id", "scan-1")]


def test_run_log_is_cut_at_its_limit(tmp_path):
    log = RunLog(tmp_path, max_bytes=100)
    log.append("r", "a" * 80)
    log.append("r", "b" * 80)
    log.append("r", "c" * 80)
    text = log.path("r").read_bytes()
    assert len(text) <= 100
    assert text.startswith(b"a" * 80)
    assert b"ccc" not in text


def _make(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    return folder

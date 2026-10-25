"""Fixture-only tests for the early-reset installer and LaunchDaemon agent."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).parent
INSTALLER = HERE / "install-early-reset-test.sh"
AGENT = HERE / "capture-early-reset.sh"


def find_shell():
    shell = shutil.which("sh")
    if shell:
        return shell
    git = shutil.which("git")
    if git:
        candidate = Path(git).resolve().parent.parent / "usr" / "bin" / "sh.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def shell_path(path: Path) -> str:
    """Convert the Windows fixture path to Git Bash's POSIX spelling."""
    value = path.resolve().as_posix()
    if len(value) > 1 and value[1] == ":":
        value = "/" + value[0].lower() + value[2:]
    return value


SHELL = find_shell()


@unittest.skipUnless(SHELL, "POSIX sh is required for fixture tests")
class EarlyResetCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="early-reset-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "fakebin"
        self.bin.mkdir()

    def fake(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def fake_shasum(self):
        # Use the test interpreter rather than GNU sha256sum, which is not
        # available on an ordinary macOS runner. Production uses macOS shasum.
        code = "import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())"
        self.fake("shasum", f'{shlex.quote(shell_path(Path(sys.executable)))} -c {shlex.quote(code)} "$3"\n')

    def env(self, **extra):
        env = os.environ.copy()
        shell_bin = str(Path(SHELL).resolve().parent)
        env["PATH"] = str(self.bin) + os.pathsep + shell_bin + os.pathsep + env.get("PATH", "")
        env.update({key: str(value) for key, value in extra.items()})
        return env

    def run_script(self, script: Path, *args, env=None):
        return subprocess.run([SHELL, str(script), *args], env=env or self.env(),
                              text=True, capture_output=True, check=False)

    def test_help_is_read_only_and_available_off_macos(self):
        trace = self.root / "help-trace"
        self.fake("uname", 'echo uname >> "$TRACE"\necho Darwin\n')
        self.fake("id", 'echo id >> "$TRACE"\necho 0\n')
        for source in (INSTALLER, AGENT):
            copy = self.root / source.name
            shutil.copyfile(source, copy)
            result = self.run_script(copy, "--help", env=self.env(TRACE=trace))
            if source == INSTALLER:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--install-and-reboot", result.stdout)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(trace.exists())

    def installer_fixture(self, baseline_hash: str, *, baseline_symlink=False,
                          partition="11111111-2222-4333-8444-555555555555"):
        payload = self.root / "payload"
        payload.mkdir()
        for name in ("plan.plist", "config-baseline.plist"):
            (payload / name).write_text("fixture\n", encoding="utf-8")
        if baseline_symlink:
            (payload / "config-baseline.plist").unlink()
            (payload / "config-baseline.plist").symlink_to(self.root / "elsewhere")

        # The plan reader is fake so the tests do not need macOS plutil.
        self.fake("uname", 'echo Darwin\n')
        self.fake("id", 'echo 0\n')
        self.fake("plutil", f'''\ncase "$2" in
PlanVersion) echo 1;;
SessionID) echo 0123456789abcdef0123456789abcdef;;
PartitionGUID) echo {partition};;
ExpectedSystemUUID) echo 12345678-1234-1234-1234-123456789abc;;
BuildRevision) echo 0123456789abcdef0123456789abcdef01234567;;
BundleVersion) echo 0.12.0;;
BaselineConfigSHA256) echo {baseline_hash};;
*) echo {"a" * 64};;
esac
''')
        # Use an isolated copy with command paths redirected only within temp.
        text = INSTALLER.read_text(encoding="utf-8")
        text = text.replace("/usr/bin/id", shell_path(self.bin / "id"))
        text = text.replace("/usr/bin/plutil", shell_path(self.bin / "plutil"))
        text = text.replace("/usr/bin/shasum", shell_path(self.bin / "shasum"))
        copy = payload / INSTALLER.name
        copy.write_text(text, encoding="utf-8")
        # This command is never reached in the rejection cases but is harmless.
        self.fake("shasum", 'exit 9\n')
        return payload, copy

    def test_invalid_plan_hash_is_rejected_before_platform_or_disk_actions(self):
        payload, script = self.installer_fixture("z" * 64)
        result = self.run_script(script, "--install-and-reboot")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid plan hash", result.stderr)
        self.assertFalse((self.root / "Library").exists())

    def test_missing_plan_hash_is_rejected_before_platform_or_disk_actions(self):
        _, script = self.installer_fixture("")
        result = self.run_script(script, "--install-and-reboot")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid plan hash", result.stderr)
        self.assertFalse((self.root / "Library").exists())

    def test_malformed_partition_uuid_is_rejected_before_platform_or_disk_actions(self):
        _, script = self.installer_fixture("a" * 64, partition="not-a-partition-uuid")
        result = self.run_script(script, "--install-and-reboot")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid PartitionGUID", result.stderr)
        self.assertFalse((self.root / "Library").exists())

    def test_symlinked_payload_is_rejected_before_platform_or_disk_actions(self):
        payload, script = self.installer_fixture("a" * 64, baseline_symlink=True)
        result = self.run_script(script, "--install-and-reboot")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing, non-regular, or symlink", result.stderr)
        self.assertFalse((self.root / "Library").exists())

    def test_installer_passive_boot_captures_then_installs_then_arms_last(self):
        session = "0123456789abcdef0123456789abcdef"
        partition = "11111111-2222-4333-8444-555555555555"
        system_uuid = "12345678-1234-1234-1234-123456789abc"
        tahoe = self.root / "Volumes" / "TAHOE"
        (self.root / "Library").mkdir()
        (self.root / "LaunchDaemons").mkdir()
        payload = tahoe / "gpu-early-test"
        payload.mkdir(parents=True)
        efi_config = tahoe / "EFI" / "OC" / "config.plist"
        efi_config.parent.mkdir(parents=True)
        payload_posix = subprocess.run([SHELL, "-c", "pwd -P"], cwd=payload, text=True,
                                       capture_output=True, check=True).stdout.strip()
        tahoe_posix = payload_posix.rsplit("/", 1)[0]
        baseline, bootstrap, armed = b"base\n", b"bootstrap\n", b"armed\n"
        (payload / "plan.plist").write_text("fixture\n", encoding="utf-8")
        (payload / "config-baseline.plist").write_bytes(baseline)
        (payload / "config-bootstrap.plist").write_bytes(bootstrap)
        (payload / "config-armed.plist").write_bytes(armed)
        efi_config.write_bytes(bootstrap)
        trace = self.root / "install-trace"
        collector = payload / "collect-gpu-survey.sh"
        collector.write_text('#!/bin/sh\nmkdir -p "$1"\necho baseline >> "$TRACE"\nexit 0\n', encoding="utf-8")
        client = payload / "mode1-reset"
        client.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        capture = payload / AGENT.name
        shutil.copyfile(AGENT, capture)
        installer = payload / INSTALLER.name
        source = INSTALLER.read_text(encoding="utf-8")
        replacements = {
            "/Library/Application Support/CobaltEarlyResetTest": shell_path(self.root / "Library" / "CobaltEarlyResetTest"),
            "/Library/LaunchDaemons/com.cobalt.early-reset-capture.plist": shell_path(self.root / "LaunchDaemons" / "com.cobalt.early-reset-capture.plist"),
            "/Volumes/TAHOE": tahoe_posix,
            "/usr/bin/id": shell_path(self.bin / "id"),
            "/usr/bin/plutil": shell_path(self.bin / "plutil"),
            "/usr/bin/shasum": shell_path(self.bin / "shasum"),
            "/usr/bin/awk": shell_path(self.bin / "awk"),
            "/usr/bin/tr": shell_path(self.bin / "tr"),
            "/usr/bin/grep": shell_path(self.bin / "grep"),
            "/usr/sbin/diskutil": shell_path(self.bin / "diskutil"),
            "/usr/sbin/ioreg": shell_path(self.bin / "ioreg"),
            "/usr/sbin/sysctl": shell_path(self.bin / "sysctl"),
            "/sbin/shutdown": shell_path(self.bin / "shutdown"),
            "sync\n": shell_path(self.bin / "sync") + "\n",
        }
        for old, new in replacements.items():
            source = source.replace(old, new)
        installer.write_text(source, encoding="utf-8")
        values = {
            "PlanVersion": "1", "SessionID": session, "PartitionGUID": partition,
            "ExpectedSystemUUID": system_uuid,
            "BuildRevision": "0123456789abcdef0123456789abcdef01234567",
            "BundleVersion": "0.12.0",
            "BaselineConfigSHA256": hashlib.sha256(baseline).hexdigest(),
            "BootstrapConfigSHA256": hashlib.sha256(bootstrap).hexdigest(),
            "ArmedConfigSHA256": hashlib.sha256(armed).hexdigest(),
            "CollectorSHA256": hashlib.sha256(collector.read_bytes()).hexdigest(),
            "ClientSHA256": hashlib.sha256(client.read_bytes()).hexdigest(),
            "CaptureAgentSHA256": hashlib.sha256(capture.read_bytes()).hexdigest(),
            "InstallerSHA256": hashlib.sha256(installer.read_bytes()).hexdigest(),
        }
        envvals = "\n".join(f"{key}) echo {value};;" for key, value in values.items())
        self.fake("plutil", f'''if [ "$1" = -lint ]; then echo daemon-lint >> "$TRACE"; exit 0; fi
case "$2" in
DiskUUID) echo {partition};;
VolumeName) echo TAHOE;;
ParentWholeDisk) echo disk9;;
BusProtocol) echo USB;;
0.IOPlatformUUID) echo "$FIXTURE_SYSTEM_UUID";;
{envvals}
*) exit 2;;
esac
''')
        self.fake("uname", 'echo Darwin\n')
        self.fake("id", 'echo 0\n')
        self.fake("diskutil", 'echo info\n')
        self.fake("ioreg", '''case " $* " in
  *" IOPlatformExpertDevice "*) echo platform;;
  *) echo '+-o CobaltNavi44Survey  <class CobaltNavi44Survey, id 0x1>'
     echo '"CobaltSurvey,BuildVersion" = "0.12.0"';;
esac
''')
        self.fake("sysctl", 'echo "cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1"\n')
        self.fake_shasum()
        self.fake("awk", 'read digest remainder\necho "$digest"\n')
        self.fake("tr", 'exec /usr/bin/tr "$@"\n')
        self.fake("grep", '''count=0
while IFS= read -r line; do case "$line" in *CobaltNavi44Survey*) count=$((count + 1));; esac; done
echo "$count"
''')
        self.fake("chown", 'echo chown >> "$TRACE"\n[ "$FAIL_CHOWN" != 1 ]\n')
        self.fake("mkdir", '''
if [ "$1" = -m ]; then shift 2; fi
/bin/mkdir "$@"
''')
        self.fake("chmod", 'echo chmod >> "$TRACE"\n')
        self.fake("sync", 'echo sync >> "$TRACE"\n')
        self.fake("mv", 'echo arm-mv >> "$TRACE"\n/bin/mv "$@"\n')
        self.fake("launchctl", 'echo forbidden-launchctl >> "$TRACE"\n')
        self.fake("shutdown", 'echo shutdown >> "$TRACE"\n')
        env = self.env(TRACE=trace, FIXTURE_SYSTEM_UUID=system_uuid)
        daemon = self.root / "LaunchDaemons" / "com.cobalt.early-reset-capture.plist"
        daemon.write_text("unrelated preexisting job\n", encoding="utf-8")
        collision = self.run_script(installer, "--install-and-reboot", env=env)
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("LaunchDaemon already exists", collision.stderr)
        self.assertEqual(daemon.read_text(encoding="utf-8"), "unrelated preexisting job\n")
        self.assertEqual(efi_config.read_bytes(), bootstrap)
        daemon.unlink()
        wrong_machine = self.run_script(installer, "--install-and-reboot",
                                        env=self.env(TRACE=trace, FIXTURE_SYSTEM_UUID="00000000-0000-0000-0000-000000000000"))
        self.assertNotEqual(wrong_machine.returncode, 0)
        self.assertIn("this is not the planned Mac", wrong_machine.stderr)
        self.assertEqual(efi_config.read_bytes(), bootstrap)
        self.assertFalse((self.root / "Library" / "CobaltEarlyResetTest").exists())
        self.assertFalse((self.root / "LaunchDaemons" / "com.cobalt.early-reset-capture.plist").exists())
        result = self.run_script(installer, "--install-and-reboot", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = trace.read_text(encoding="utf-8").splitlines()
        self.assertLess(events.index("baseline"), events.index("daemon-lint"))
        self.assertLess(events.index("daemon-lint"), events.index("arm-mv"))
        self.assertLess(events.index("arm-mv"), events.index("shutdown"))
        self.assertNotIn("forbidden-launchctl", events)
        self.assertEqual(efi_config.read_bytes(), armed)
        self.assertTrue((self.root / "Library" / "CobaltEarlyResetTest" / "pending-session").exists())
        self.assertTrue((self.root / "LaunchDaemons" / "com.cobalt.early-reset-capture.plist").exists())
        self.assertEqual(events[-1], "shutdown")

        # Re-run from the same fixture with an injected post-copy chown failure.
        # Only files this installer created are rolled back; the baseline USB
        # capture remains available for diagnosis.
        import shutil as _shutil
        _shutil.rmtree(self.root / "Library" / "CobaltEarlyResetTest")
        (self.root / "LaunchDaemons" / "com.cobalt.early-reset-capture.plist").unlink()
        _shutil.rmtree(tahoe / f"EARLY-RESET-{session}")
        efi_config.write_bytes(bootstrap)
        fail_trace = self.root / "failure-trace"
        failed = self.run_script(installer, "--install-and-reboot",
                                 env=self.env(TRACE=fail_trace, FIXTURE_SYSTEM_UUID=system_uuid, FAIL_CHOWN="1"))
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse((self.root / "Library" / "CobaltEarlyResetTest").exists())
        self.assertFalse((self.root / "LaunchDaemons" / "com.cobalt.early-reset-capture.plist").exists())
        self.assertEqual(efi_config.read_bytes(), baseline)
        self.assertTrue((tahoe / f"EARLY-RESET-{session}" / "baseline").exists())
        self.assertNotIn("shutdown", fail_trace.read_text(encoding="utf-8"))

    def test_agent_leaves_pending_setup_untouched_on_non_test_boot(self):
        resident = self.root / "resident"
        resident.mkdir()
        session = "0123456789abcdef0123456789abcdef"
        (resident / "pending-session").write_text(session + "\n", encoding="utf-8")
        (resident / "plan.plist").write_text("fixture\n", encoding="utf-8")
        collector = resident / "collect-gpu-survey.sh"
        collector.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        client = resident / "mode1-reset"
        client.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        agent = self.root / AGENT.name
        text = AGENT.read_text(encoding="utf-8")
        text = text.replace("/Library/Application Support/CobaltEarlyResetTest", shell_path(resident))
        text = text.replace("/var/log/cobalt-early-reset-capture.log", shell_path(self.root / "agent.log"))
        text = text.replace("/usr/bin/plutil", shell_path(self.bin / "plutil"))
        text = text.replace("/usr/bin/shasum", shell_path(self.bin / "shasum"))
        text = text.replace("/usr/bin/awk", shell_path(self.bin / "awk"))
        text = text.replace("/usr/bin/id", shell_path(self.bin / "id"))
        text = text.replace("/usr/sbin/sysctl", shell_path(self.bin / "sysctl"))
        agent.write_text(text, encoding="utf-8")
        shutil.copyfile(agent, resident / "capture-early-reset.sh")

        hashes = {
            "PlanVersion": "1",
            "BundleVersion": "0.12.0",
            "BuildRevision": "0123456789abcdef0123456789abcdef01234567",
            "SessionID": session,
            "PartitionGUID": "11111111-2222-4333-8444-555555555555",
            "ExpectedSystemUUID": "12345678-1234-1234-1234-123456789abc",
            "BaselineConfigSHA256": hashlib.sha256(b"baseline").hexdigest(),
            "ArmedConfigSHA256": "1" * 64,
            "CollectorSHA256": hashlib.sha256(collector.read_bytes()).hexdigest(),
            "ClientSHA256": hashlib.sha256(client.read_bytes()).hexdigest(),
            "CaptureAgentSHA256": hashlib.sha256(text.encode()).hexdigest(),
        }
        (resident / "config-baseline.plist").write_bytes(b"baseline")
        # Keep the executable source hash aligned with the script copied here.
        hashes["CaptureAgentSHA256"] = hashlib.sha256(agent.read_bytes()).hexdigest()
        envvals = "\n".join(f"{key}) echo {value};;" for key, value in hashes.items())
        self.fake("plutil", f'case "$2" in\n{envvals}\n*) exit 2;;\nesac\n')
        self.fake("uname", 'echo Darwin\n')
        self.fake("id", 'echo 0\n')
        self.fake("sysctl", 'echo "survey=1"\n')
        self.fake_shasum()
        self.fake("awk", 'read digest remainder\necho "$digest"\n')
        result = self.run_script(agent, "--capture-once", env=self.env())
        self.assertEqual(result.returncode, 0, result.stderr + "\n" + (self.root / "agent.log").read_text() if (self.root / "agent.log").exists() else result.stderr)
        self.assertTrue((resident / "pending-session").exists())
        self.assertFalse((resident / f"consumed-session-{session}").exists())
        self.assertFalse((self.root / "agent.log").exists())

    def test_matching_early_boot_disarms_before_one_failed_collection_then_reboots(self):
        resident = self.root / "resident"
        resident.mkdir()
        session = "0123456789abcdef0123456789abcdef"
        partition = "11111111-2222-4333-8444-555555555555"
        system_uuid = "12345678-1234-1234-1234-123456789abc"
        tahoe = self.root / "Volumes" / "TAHOE"
        efi = tahoe
        session_dir = tahoe / f"EARLY-RESET-{session}"
        session_dir.mkdir(parents=True)
        (efi / "EFI" / "OC").mkdir(parents=True)
        baseline = b"passive-baseline-config\n"
        armed = b"armed-one-shot-config\n"
        (resident / "config-baseline.plist").write_bytes(baseline)
        config = efi / "EFI" / "OC" / "config.plist"
        config.write_bytes(armed)
        (resident / "pending-session").write_text(session + "\n", encoding="utf-8")
        (resident / "plan.plist").write_text("fixture\n", encoding="utf-8")
        (self.root / "daemon.plist").write_text("known daemon\n", encoding="utf-8")

        trace = self.root / "trace.log"
        collector = resident / "collect-gpu-survey.sh"
        collector.write_text(
            '#!/bin/sh\nprintf "collector config=" >> "$TRACE"\n'
            'cat "$FAKE_EFI_CONFIG" >> "$TRACE"\n'
            'echo "collector-call" >> "$TRACE"\nexit 42\n', encoding="utf-8")
        client = resident / "mode1-reset"
        client.write_text('#!/bin/sh\necho "client:$*" >> "$TRACE"\nexit 0\n', encoding="utf-8")
        agent = self.root / AGENT.name
        text = AGENT.read_text(encoding="utf-8")
        replacements = {
            "/Library/Application Support/CobaltEarlyResetTest": shell_path(resident),
            "/Library/LaunchDaemons/com.cobalt.early-reset-capture.plist": shell_path(self.root / "daemon.plist"),
            "/Volumes/TAHOE": shell_path(tahoe),
            "/var/log/cobalt-early-reset-capture.log": shell_path(self.root / "agent.log"),
            "/usr/bin/plutil": shell_path(self.bin / "plutil"),
            "/usr/bin/shasum": shell_path(self.bin / "shasum"),
            "/usr/bin/awk": shell_path(self.bin / "awk"),
            "/usr/bin/id": shell_path(self.bin / "id"),
            "/usr/sbin/sysctl": shell_path(self.bin / "sysctl"),
            "/usr/sbin/ioreg": shell_path(self.bin / "ioreg"),
            "/usr/sbin/diskutil": shell_path(self.bin / "diskutil"),
            "/bin/sync": shell_path(self.bin / "sync"),
            "/bin/sleep": shell_path(self.bin / "sleep"),
            "/bin/launchctl": shell_path(self.bin / "launchctl"),
            "/bin/rm": shell_path(self.bin / "rm"),
            "/sbin/shutdown": shell_path(self.bin / "shutdown"),
        }
        for source, replacement in replacements.items():
            text = text.replace(source, replacement)
        agent.write_text(text, encoding="utf-8")
        shutil.copyfile(agent, resident / "capture-early-reset.sh")

        hashes = {
            "PlanVersion": "1", "BundleVersion": "0.12.0",
            "BuildRevision": "0123456789abcdef0123456789abcdef01234567",
            "SessionID": session, "PartitionGUID": partition,
            "ExpectedSystemUUID": system_uuid,
            "BaselineConfigSHA256": hashlib.sha256(baseline).hexdigest(),
            "ArmedConfigSHA256": hashlib.sha256(armed).hexdigest(),
            "CollectorSHA256": hashlib.sha256(collector.read_bytes()).hexdigest(),
            "ClientSHA256": hashlib.sha256(client.read_bytes()).hexdigest(),
            "CaptureAgentSHA256": hashlib.sha256(agent.read_bytes()).hexdigest(),
        }
        envvals = "\n".join(f"{key}) echo {value};;" for key, value in hashes.items())
        self.fake("plutil", f'''case "$2" in
0.IOPlatformUUID) echo "$FIXTURE_SYSTEM_UUID";;
DiskUUID) echo {partition};;
ParentWholeDisk) echo disk9;;
BusProtocol) echo USB;;
{envvals}
*) exit 2;;
esac
''')
        self.fake("uname", 'echo Darwin\n')
        self.fake("id", 'echo 0\n')
        self.fake("sysctl", 'echo "cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1 cobalt-survey-mode1boot=1 cobalt-survey-mode1=0 cobalt-survey-aperture=0 cobalt-survey-staging=0 cobalt-survey-kdb=0 cobalt-survey-spl=0 cobalt-survey-presos=0 cobalt-survey-sos=0"\n')
        self.fake("ioreg", '''
case " $* " in
  *" IOPlatformExpertDevice "*) echo platform;;
  *)
     if [ "$DRIVER_MISSING" = 1 ]; then echo 'ioreg driver missing' >&2; exit 7; fi
     echo '"CobaltSurvey,BuildVersion" = "0.12.0"'
     echo '"CobaltSurvey,Mode1ResetEarlyRequested" = Yes'
     echo '"CobaltSurvey,Mode1ResetTrigger" = "early-boot"';;
esac
''')
        self.fake("diskutil", 'echo fixture-info\n')
        self.fake("sleep", 'echo sleep >> "$TRACE"\n')
        self.fake_shasum()
        self.fake("awk", 'read digest remainder\necho "$digest"\n')
        self.fake("sync", 'echo sync >> "$TRACE"\n')
        self.fake("launchctl", 'echo forbidden-launchctl >> "$TRACE"\n')
        self.fake("rm", 'echo rm >> "$TRACE"\n/bin/rm "$@"\n')
        self.fake("shutdown", 'echo shutdown >> "$TRACE"\n')
        env = self.env(TRACE=trace, FAKE_EFI_CONFIG=config, FIXTURE_SYSTEM_UUID="00000000-0000-0000-0000-000000000000")
        wrong = self.run_script(agent, "--capture-once", env=env)
        self.assertEqual(wrong.returncode, 0, wrong.stderr)
        self.assertEqual(config.read_bytes(), armed)
        self.assertTrue((resident / "pending-session").exists())
        self.assertFalse(trace.exists())
        env["FIXTURE_SYSTEM_UUID"] = system_uuid
        env["DRIVER_MISSING"] = "1"
        result = self.run_script(agent, "--capture-once", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        trace_text = trace.read_text(encoding="utf-8")
        self.assertIn("collector config=passive-baseline-config", trace_text)
        self.assertEqual(trace_text.count("collector-call"), 1)
        self.assertIn("shutdown", trace_text)
        self.assertNotIn("forbidden-launchctl", trace_text)
        self.assertFalse((self.root / "daemon.plist").exists())
        self.assertFalse((resident / "pending-session").exists())
        receipt = (resident / f"completion-{session}.txt").read_text(encoding="utf-8")
        self.assertIn("early_requested=not-observed", receipt)
        self.assertIn("trigger=not-observed", receipt)
        self.assertIn("build_version=not-observed", receipt)
        self.assertIn("driver_ioreg_exit=7", receipt)
        self.assertIn("collector_exit=42", receipt)
        self.assertEqual(config.read_bytes(), baseline)
        self.assertTrue((session_dir / f"completion-{session}.txt").exists())
        self.assertTrue((session_dir / "capture-agent.log").exists())
        self.assertIn("client:--inspect-peers", trace_text)
        self.assertNotIn("--run", trace_text)


if __name__ == "__main__":
    unittest.main()

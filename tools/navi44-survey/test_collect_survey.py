"""Host-side tests for collect-survey.sh using fake macOS commands."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name("collect-survey.sh")


def find_shell():
    shell = shutil.which("sh")
    if shell:
        return shell
    git = shutil.which("git")
    if git:
        bundled = Path(git).resolve().parent.parent / "usr" / "bin" / "sh.exe"
        if bundled.is_file():
            return str(bundled)
    return None


SHELL = find_shell()


@unittest.skipUnless(SHELL, "POSIX sh is required to test the collector")
class SurveyCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="navi44 survey ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.script = self.root / "script path with spaces" / "collect-survey.sh"
        self.script.parent.mkdir()
        shutil.copyfile(SOURCE, self.script)
        self.bin = self.root / "fake-commands"
        self.bin.mkdir()

    def fake(self, name: str, source: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + source, encoding="utf-8")
        path.chmod(0o755)

    def base_commands(self, *, service=True, log_exit=0, sw_exit=0):
        self.fake("sw_vers", f'printf "ProductName: macOS\\nProductVersion: Tahoe\\n"\nexit {sw_exit}\n')
        self.fake("uname", 'printf "Darwin test-host 25.0.0 arm64\\n"\n')
        text = '+-o CobaltNavi44Survey  <class CobaltNavi44Survey, id 0x123>\n    "ProbeState" = "attached"\n'
        self.fake("ioreg", (
            'printf "CALL\\n" >> "$ARG_LOG_DIR/ioreg.args"\n'
            'for arg in "$@"; do printf "<%s>\\n" "$arg" >> "$ARG_LOG_DIR/ioreg.args"; done\n'
            'case " $* " in\n'
            '  *" -a "*) printf "<?xml version=\\"1.0\\"?><plist><dict><key>IOClass</key><string>CobaltNavi44Survey</string></dict></plist>\\n";;\n'
            f'  *) {"printf " + repr(text) if service else ":"};;\n'
            'esac\n'
        ))
        self.fake("kmutil", 'echo "kmutil unavailable in fixture" >&2\nexit 71\n')
        self.fake("log", (
            'printf "CALL\\n" >> "$ARG_LOG_DIR/log.args"\n'
            'for arg in "$@"; do printf "<%s>\\n" "$arg" >> "$ARG_LOG_DIR/log.args"; done\n'
            f'echo "log fixture diagnostic" >&2\nexit {log_exit}\n'
        ))

    def run_collector(self, *, output=None, extra_env=None):
        env = os.environ.copy()
        env["PATH"] = str(self.bin) + os.pathsep + str(Path(SHELL).parent) + os.pathsep + env.get("PATH", "")
        env["ARG_LOG_DIR"] = str(self.root)
        if extra_env:
            env.update(extra_env)
        args = [SHELL, str(self.script)]
        if output is not None:
            args.append(str(output))
        completed = subprocess.run(args, env=env, text=True, capture_output=True, check=False)
        reports = list(Path(output or self.script.parent).glob("CobaltNavi44Survey-*"))
        if not reports:
            self.fail(f"collector did not create a report; stdout={completed.stdout!r}, stderr={completed.stderr!r}")
        return completed, reports[0]

    def test_attached_service_collects_targeted_data_and_records_best_effort_failures(self):
        self.base_commands(log_exit=43)
        completed, report = self.run_collector(output=self.root / "output path")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("CobaltNavi44Survey", (report / "ioreg-service.txt").read_text())
        self.assertIn("CobaltNavi44Survey", (report / "ioreg-service-xml.txt").read_text())
        self.assertIn("exit 71", (report / "status.txt").read_text())
        self.assertIn("exit 43", (report / "status.txt").read_text())
        self.assertIn("log fixture diagnostic", (report / "boot-log.stderr.txt").read_text())
        self.assertFalse((report / "gpu-provider-clients.txt").exists())
        self.assertIn("instance output captured", (report / "README.txt").read_text())
        self.assertEqual(
            (self.root / "ioreg.args").read_text(),
            "CALL\n<-r>\n<-c>\n<CobaltNavi44Survey>\n<-l>\n<-w0>\n"
            "CALL\n<-r>\n<-c>\n<CobaltNavi44Survey>\n<-a>\n",
        )
        self.assertEqual(
            (self.root / "log.args").read_text(),
            'CALL\n<show>\n<--last>\n<15m>\n<--style>\n<compact>\n'
            '<--predicate>\n<process == "kernel" AND eventMessage CONTAINS "CobaltNavi44Survey">\n',
        )

    @unittest.skipIf(os.name == "nt", "Windows filesystems do not expose executable mode bits to POSIX sh")
    def test_optional_peer_inventory_is_captured_and_failure_is_best_effort(self):
        self.base_commands()
        client = self.script.parent / "mode1-reset"
        client.write_text('#!/bin/sh\necho "peer inventory refused" >&2\nexit 5\n', encoding="utf-8")
        client.chmod(0o755)
        completed, report = self.run_collector(output=self.root / "peer output")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("peer inventory refused", (report / "gpu-provider-clients.stderr.txt").read_text())
        self.assertTrue((report / "gpu-provider-clients.txt").exists())
        self.assertIn("gpu-provider-clients: exit 5", (report / "status.txt").read_text())

    def test_empty_service_output_is_unambiguously_exit_two(self):
        self.base_commands(service=False)
        completed, report = self.run_collector(output=self.root / "empty output")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("MISSING", (report / "README.txt").read_text())
        self.assertIn("service was not found", completed.stderr)

    def test_missing_required_command_is_collection_failure_one(self):
        self.base_commands(service=True)
        self.fake("ioreg", 'echo "ioreg: command not found" >&2\nexit 127\n')
        completed, report = self.run_collector(output=self.root / "missing output")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("exit 127", (report / "status.txt").read_text())
        self.assertIn("not found", (report / "ioreg-service.stderr.txt").read_text())

    def test_required_command_failure_takes_precedence_over_missing_service(self):
        self.base_commands(service=False, sw_exit=1)
        completed, report = self.run_collector(output=self.root / "partial output")
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("Service status: MISSING", (report / "README.txt").read_text())
        self.assertIn("sw_vers: exit 1", (report / "status.txt").read_text())


if __name__ == "__main__":
    unittest.main()

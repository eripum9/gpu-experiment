"""Isolated shell fixtures; production scripts have no test mode or path override."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).parent
INSTALLER = HERE / "install-early-reset-test.sh"
AGENT = HERE / "capture-early-reset.sh"
SESSION = "0123456789abcdef0123456789abcdef"
PARTITION = "11111111-2222-4333-8444-555555555555"
SYSTEM_UUID = "12345678-1234-1234-1234-123456789abc"
NONCE = "fedcba9876543210fedcba9876543210"


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


def shell_path(path):
    value = Path(path).resolve().as_posix()
    return "/" + value[0].lower() + value[2:] if len(value) > 1 and value[1] == ":" else value


SHELL = find_shell()


@unittest.skipUnless(SHELL, "POSIX sh is required for fixture tests")
class EarlyResetCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="early-reset-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.resident = self.root / "Library" / "CobaltEarlyResetTest"
        self.daemons = self.root / "LaunchDaemons"
        self.daemons.mkdir()
        self.resident.parent.mkdir()
        self.app = self.root / "Applications" / "CobaltEarlyCapture.app"
        self.app.parent.mkdir()
        self.tahoe = self.root / "Volumes" / "TAHOE"
        self.payload = self.tahoe / "gpu-early-test"
        self.payload.mkdir(parents=True)
        self.config = self.tahoe / "EFI" / "OC" / "config.plist"
        self.config.parent.mkdir(parents=True)
        self.config.write_bytes(b"bootstrap\n")
        self.trace = self.root / "trace"
        self.log = self.root / "agent.log"
        self.daemon = self.daemons / "com.cobalt.early-reset-capture.plist"
        self.preflight = self.daemons / "com.cobalt.early-reset-preflight.plist"
        self.session_dir = self.tahoe / ("EARLY-RESET-" + SESSION)
        self.python = shlex.quote(shell_path(sys.executable))
        self.setup_commands()
        self.setup_payload()

    def fake(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8", newline="\n")
        path.chmod(0o755)
        return path

    def python_fake(self, name, code):
        return self.fake(name, "exec " + self.python + " -c " + shlex.quote(code) + ' "$@"\n')

    def setup_commands(self):
        self.fake("uname", "echo Darwin\n")
        self.fake("id", "echo 0\n")
        self.python_fake("stat", """import os,stat,sys
fmt=sys.argv[2]; path=sys.argv[3]
if fmt=='%u:%g': print('0:0') # Ownership is mocked; the Windows fixture host has no root:wheel.
elif fmt=='%Lp':
 import json
 actual=stat.S_IMODE(os.stat(path).st_mode)
 key=path
 if os.name=='nt' and key.startswith('/c/'): key='C:'+key[2:]
 try: mode=json.load(open(os.environ['FAKE_MODE_DB'])).get(key, actual) if os.name=='nt' else actual
 except (OSError,ValueError): mode=actual
 print(format(mode, 'o'))
else: sys.exit(2)
""")
        self.python_fake("chmod", """import json,os,sys
db=os.environ['FAKE_MODE_DB']
try: modes=json.load(open(db))
except (OSError,ValueError): modes={}
mode=int(sys.argv[1],8)
for path in sys.argv[2:]:
 try:
  if os.name!='nt': os.chmod(path,mode)
 except OSError: pass
 modes[path]=mode
json.dump(modes,open(db,'w'))
""")
        self.python_fake("mkdir", """import json,os,sys
args=sys.argv[1:]; parents='-p' in args; mode=None
if '-m' in args:
 i=args.index('-m'); mode=int(args[i+1],8); del args[i:i+2]
args=[a for a in args if a!='-p']
db=os.environ['FAKE_MODE_DB']
try: modes=json.load(open(db))
except (OSError,ValueError): modes={}
for path in args:
 open(os.environ['TRACE'],'a').write('mkdir:'+path+'\\n')
 try: os.makedirs(path,exist_ok=parents)
 except FileExistsError: sys.exit(1)
 if mode is not None:
  if os.name!='nt': os.chmod(path,mode)
  modes[path]=mode
json.dump(modes,open(db,'w'))
""")
        self.fake("codesign", 'echo signature-verify >> "$TRACE"\n')
        self.fake("uuidgen", "echo " + NONCE + "\n")
        self.fake("chown", '[ "${FAIL_CHOWN-0}" != 1 ]\n')
        self.fake("sleep", 'echo poll-sleep >> "$TRACE"\n')
        self.fake("sync", 'echo sync >> "$TRACE"\n')
        self.fake("shutdown", 'echo shutdown >> "$TRACE"\n')
        self.python_fake("plutil", """import sys,plistlib
args=sys.argv[1:]
if args[0]=='-lint':
 plistlib.loads(open(args[1],'rb').read()); sys.exit(0)
key=args[1]; path=args[-1]
data=sys.stdin.buffer.read() if path=='-' else open(path,'rb').read()
obj=plistlib.loads(data)
try:
 for part in key.split('.'):
  obj=obj[int(part)] if isinstance(obj,list) else obj[part]
 print(obj)
except (KeyError,ValueError,IndexError,TypeError): sys.exit(1)
""")
        self.python_fake("shasum", """import sys,pathlib,hashlib,os
path=pathlib.Path(sys.argv[3])
if os.environ.get('DENY_USB')=='1' and os.environ.get('BACKGROUND')=='1' and path.name=='config.plist':
 print('shasum: config.plist: Operation not permitted',file=sys.stderr); sys.exit(13)
print(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path))
""")
        info = plistlib.dumps(dict(DiskUUID=PARTITION, VolumeName="TAHOE", ParentWholeDisk="disk9", BusProtocol="USB")).decode()
        self.fake("diskutil", "printf '%s' " + shlex.quote(info) + "\n")
        platform = plistlib.dumps([dict(IOPlatformUUID=SYSTEM_UUID)]).decode()
        self.fake("ioreg", """case " $* " in
*" IOPlatformExpertDevice "*) printf '%s' """ + shlex.quote(platform) + """;;
*)
 echo 'driver-ioreg' >> "$TRACE"
 [ "${DRIVER_MISSING-0}" != 1 ] || { echo 'ioreg driver missing' >&2; exit 7; }
 echo '+-o CobaltNavi44Survey  <class CobaltNavi44Survey, id 0x1>'
 echo '\"CobaltSurvey,BuildVersion\" = \"0.12.0\"'
 echo '\"CobaltSurvey,Mode1ResetEarlyRequested\" = Yes'
 echo '\"CobaltSurvey,Mode1ResetTrigger\" = \"early-boot\"';;
esac
""")
        self.fake("sysctl", 'echo "$BOOTARGS"\n')
        for name in ("cp", "mv", "rm"):
            fail_arm_copy = 'case "$*" in *config.plist.early-reset.tmp) [ "${FAIL_ARM_COPY-0}" != 1 ] || exit 1;; esac\n' if name == "cp" else ""
            self.fake(name, 'echo "' + name + ':$*" >> "$TRACE"\n' + fail_arm_copy + 'exec /bin/' + name + ' "$@"\n')
        self.fake("rmdir", 'echo "rmdir:$*" >> "$TRACE"\nexec /bin/rmdir "$@"\n')
        self.fake("launchctl", """echo "launchctl:$*" >> "$TRACE"
case "$1" in
bootstrap) [ "$2" = system ] && [ "$3" = "$PREFLIGHT" ];;
kickstart) [ "$2" = system/com.cobalt.early-reset-preflight ] || exit 2
 BACKGROUND=1 "$LAUNCHER" --probe-agent || true
 # kickstart reports job dispatch success; installer observes probe result file.
 exit 0;;
bootout) [ "$2" = system/com.cobalt.early-reset-preflight ];;
*) exit 2;;
esac
""")

    def rewrite(self, source):
        text = source.read_text(encoding="utf-8")
        replacements = {
            "/Library/Application Support/CobaltEarlyResetTest": shell_path(self.resident),
            "/Library/LaunchDaemons/com.cobalt.early-reset-capture.plist": shell_path(self.daemon),
            "/Library/LaunchDaemons/com.cobalt.early-reset-preflight.plist": shell_path(self.preflight),
            "/Applications/CobaltEarlyCapture.app": shell_path(self.app),
            "/Volumes/TAHOE": shell_path(self.tahoe),
            "/var/log/cobalt-early-reset-capture.log": shell_path(self.log),
        }
        for name, prefix in (("id", "/usr/bin/"), ("stat", "/usr/bin/"), ("codesign", "/usr/bin/"),
                             ("uuidgen", "/usr/bin/"), ("plutil", "/usr/bin/"), ("shasum", "/usr/bin/"),
                             ("diskutil", "/usr/sbin/"), ("ioreg", "/usr/sbin/"), ("sysctl", "/usr/sbin/"),
                             ("launchctl", "/bin/"), ("sleep", "/bin/"), ("sync", "/bin/"), ("shutdown", "/sbin/")):
            replacements[prefix + name] = shell_path(self.bin / name)
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def setup_payload(self):
        self.collector = self.payload / "collect-gpu-survey.sh"
        self.collector.write_text('#!/bin/sh\nmkdir -p "$1"\necho "collector:$1:$(cat "$EFI_CONFIG")" >> "$TRACE"\necho evidence > "$1/survey.txt"\nexit "${COLLECTOR_EXIT-0}"\n' , encoding="utf-8", newline="\n")
        self.client = self.payload / "mode1-reset"
        self.client.write_text('#!/bin/sh\necho "client:$*" >> "$TRACE"\n[ "$1" = --inspect-peers ]\n', encoding="utf-8", newline="\n")
        self.client.chmod(0o755)
        self.capture = self.payload / AGENT.name
        self.capture.write_text(self.rewrite(AGENT), encoding="utf-8", newline="\n")
        self.installer = self.payload / INSTALLER.name
        self.installer.write_text(self.rewrite(INSTALLER), encoding="utf-8", newline="\n")
        source_app = self.payload / "CobaltEarlyCapture.app" / "Contents"
        (source_app / "MacOS").mkdir(parents=True)
        (source_app / "_CodeSignature").mkdir()
        launcher = source_app / "MacOS" / "CobaltEarlyCapture"
        launcher.write_text('#!/bin/sh\necho "native:$*:background=${BACKGROUND-0}" >> "$TRACE"\n'
                            'case "$1" in --probe-agent) [ "${BACKGROUND-0}" = 1 ] || exit 2; mode=--probe-usb;; '
                            '--run-agent) mode=--capture-once;; *) exit 2;; esac\n'
                            'exec /bin/sh ' + shlex.quote(shell_path(self.resident / AGENT.name)) + ' "$mode"\n',
                            encoding="utf-8", newline="\n")
        launcher.chmod(0o755)
        (source_app / "Info.plist").write_bytes(plistlib.dumps(dict(CFBundleVersion="1.0.0")))
        (source_app / "_CodeSignature" / "CodeResources").write_bytes(b"fixture signature")
        self.values = dict(PlanVersion=1, BundleVersion="0.12.0", BuildRevision="0123456789abcdef0123456789abcdef01234567",
                           SessionID=SESSION, PartitionGUID=PARTITION, ExpectedSystemUUID=SYSTEM_UUID)
        for name, content, key in (("config-baseline.plist", b"base\n", "BaselineConfigSHA256"),
                                   ("config-bootstrap.plist", b"bootstrap\n", "BootstrapConfigSHA256"),
                                   ("config-armed.plist", b"armed\n", "ArmedConfigSHA256")):
            (self.payload / name).write_bytes(content)
            self.values[key] = hashlib.sha256(content).hexdigest()
        for path, key in ((self.collector, "CollectorSHA256"), (self.client, "ClientSHA256"),
                          (self.capture, "CaptureAgentSHA256"), (self.installer, "InstallerSHA256"),
                          (launcher, "LauncherSHA256"), (source_app / "Info.plist", "AppInfoSHA256"),
                          (source_app / "_CodeSignature" / "CodeResources", "AppResourcesSHA256")):
            self.values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_plan()

    def write_plan(self):
        (self.payload / "plan.plist").write_bytes(plistlib.dumps(self.values))

    def env(self, **extra):
        env = os.environ.copy()
        env.update(PATH=str(self.bin) + os.pathsep + str(Path(SHELL).resolve().parent) + os.pathsep + env.get("PATH", ""),
                   TRACE=shell_path(self.trace), EFI_CONFIG=shell_path(self.config),
                   FAKE_MODE_DB=shell_path(self.root / "fake-modes.json"),
                   LAUNCHER=shell_path(self.app / "Contents" / "MacOS" / "CobaltEarlyCapture"),
                   PREFLIGHT=shell_path(self.preflight),
                   BOOTARGS="cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1")
        env.update({key: str(value) for key, value in extra.items()})
        return env

    def run_script(self, path, *args, **extra):
        return subprocess.run([SHELL, shell_path(path), *args], env=self.env(**extra), text=True, capture_output=True, check=False)

    def install(self, **extra):
        return self.run_script(self.installer, "--install-and-reboot", **extra)

    def events(self):
        return self.trace.read_text(encoding="utf-8") if self.trace.exists() else ""

    def prepare_agent(self):
        self.resident.mkdir()
        for name in ("plan.plist", "config-baseline.plist", "collect-gpu-survey.sh", "mode1-reset", AGENT.name):
            shutil.copyfile(self.payload / name, self.resident / name)
        (self.resident / "mode1-reset").chmod(0o755)
        (self.resident / "pending-session").write_text(SESSION + "\n")
        self.session_dir.mkdir()
        self.config.write_bytes(b"armed\n")
        self.daemon.write_text("known job")

    def run_agent(self, **extra):
        defaults = dict(BACKGROUND="1", BOOTARGS="cobalt-survey=1 cobalt-survey-indexed=1 cobalt-survey-state=1 cobalt-survey-mode1boot=1")
        defaults.update(extra)
        return self.run_script(self.resident / AGENT.name, "--capture-once", **defaults)

    def test_help_is_read_only(self):
        for source in (INSTALLER, AGENT):
            result = self.run_script(source, "--help")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.trace.exists())

    def test_invalid_or_missing_hash_and_wrong_partition_fail_before_mutation(self):
        for key, bad, message in (("BaselineConfigSHA256", "z" * 64, "invalid plan hash"),
                                  ("BaselineConfigSHA256", "", "invalid plan hash"),
                                  ("PartitionGUID", "bad", "invalid PartitionGUID")):
            saved = self.values[key]
            self.values[key] = bad
            self.write_plan()
            result = self.install()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)
            self.assertFalse(self.resident.exists())
            self.values[key] = saved

    def test_wrong_machine_uuid_refuses_before_install_mutation(self):
        self.values["ExpectedSystemUUID"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        self.write_plan()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("this is not the planned Mac", result.stderr)
        self.assertFalse(self.app.exists())
        self.assertFalse(self.resident.exists())
        self.assertFalse(self.daemon.exists())
        self.assertEqual(self.config.read_bytes(), b"bootstrap\n")

    def test_valid_but_wrong_partition_guid_refuses_usb_identity(self):
        self.values["PartitionGUID"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        self.write_plan()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TAHOE partition UUID does not match plan", result.stderr)
        self.assertFalse(self.app.exists())
        self.assertFalse(self.resident.exists())
        self.assertFalse(self.daemon.exists())
        self.assertEqual(self.config.read_bytes(), b"bootstrap\n")

    def test_preexisting_resident_directory_is_preserved(self):
        self.resident.mkdir()
        marker = self.resident / "unrelated"
        marker.write_text("keep")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "keep")
        self.assertEqual(self.config.read_bytes(), b"bootstrap\n")

    def test_payload_hash_failure_is_explicit(self):
        self.fake("shasum", "echo 'Operation not permitted' >&2\nexit 13\n")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot hash payload file", result.stderr)
        self.assertNotIn("payload hash mismatch", result.stderr)

    def test_permission_failure_in_native_launchd_context_preserves_bootstrap_for_retry(self):
        # Terminal-context shasum works; only the child of the fixture job is denied.
        result = self.install(DENY_USB="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("Full Disk Access", result.stderr)
        self.assertEqual(self.config.read_bytes(), b"bootstrap\n")
        self.assertTrue(self.app.is_dir())
        self.assertFalse(self.resident.exists())
        self.assertFalse(self.preflight.exists())
        self.assertFalse(self.daemon.exists())
        self.assertFalse(self.session_dir.exists())
        events = self.events()
        self.assertIn("native:--probe-agent:background=1", events)
        self.assertIn("launchctl:bootout system/com.cobalt.early-reset-preflight", events)
        self.assertNotIn("shutdown", events)
        self.assertNotIn("collector:", events)
        self.assertIn("cannot hash file (permission/access failure)", self.log.read_text())
        self.assertNotIn("neither planned", self.log.read_text())
        # FDA retry reuses the exact installed app and the same session.
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr + self.log.read_text())

    def test_positive_install_native_probe_nonce_cleanup_and_arm_last(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr + (self.log.read_text() if self.log.exists() else ""))
        events = self.events()
        self.assertLess(events.index("native:--probe-agent"), events.index("collector:"))
        self.assertLess(events.index("collector:"), events.index("config.plist.early-reset.tmp"))
        self.assertLess(events.index("config.plist.early-reset.tmp"), events.index("shutdown"))
        nonce_path = ".cobalt-early-probe-" + SESSION + "-" + NONCE + ".tmp"
        self.assertIn(nonce_path + ".copy", events)
        self.assertIn(nonce_path + ".verified", events)
        output_probe = ".cobalt-early-output-probe-" + SESSION + "-" + NONCE
        self.assertIn(".cobalt-early-output-probe-" + SESSION + "-" + NONCE, events)
        self.assertIn("mv:" + shell_path(self.tahoe / output_probe / "source") + " " + shell_path(self.tahoe / output_probe / "verified"), events)
        self.assertIn("rm:" + shell_path(self.tahoe / output_probe / "verified"), events)
        self.assertIn("rmdir:" + shell_path(self.tahoe / output_probe), events)
        self.assertIn("rm:", events)
        self.assertEqual(list(self.config.parent.glob(".cobalt-early-probe-*")), [])
        self.assertEqual(list(self.tahoe.glob(".cobalt-early-output-probe-*")), [])
        self.assertEqual(list(self.resident.glob("probe-*")), [])
        self.assertEqual(self.config.read_bytes(), b"armed\n")
        self.assertTrue((self.resident / "pending-session").exists())
        daemon = plistlib.loads(self.daemon.read_bytes())
        self.assertEqual(daemon["ProgramArguments"], [shell_path(self.app / "Contents" / "MacOS" / "CobaltEarlyCapture"), "--run-agent"])
        self.assertEqual(events.count("launchctl:kickstart"), 1)
        self.assertNotIn("native:--run-agent", events)
        self.assertEqual(events.splitlines()[-1], "shutdown")

    def test_unknown_app_and_existing_daemon_are_preserved(self):
        self.app.mkdir()
        marker = self.app / "unrelated"
        marker.write_text("keep")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "keep")
        marker.unlink()
        self.app.rmdir()
        self.daemon.write_text("unrelated daemon")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.daemon.read_text(), "unrelated daemon")
        self.assertEqual(self.config.read_bytes(), b"bootstrap\n")

    def test_existing_capture_app_with_unsafe_mode_is_rejected(self):
        shutil.copytree(self.payload / "CobaltEarlyCapture.app", self.app)
        self.app.chmod(0o777)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("capture app directory permissions are unsafe", result.stderr)
        self.assertTrue((self.app / "Contents" / "Info.plist").exists())
        self.assertFalse(self.resident.exists())
        self.assertFalse(self.daemon.exists())
        self.assertEqual(self.config.read_bytes(), b"bootstrap\n")

    def test_arm_copy_failure_restores_baseline_and_cleans_partial_setup(self):
        result = self.install(FAIL_ARM_COPY="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("config-armed.plist", self.events())
        self.assertEqual(self.config.read_bytes(), b"base\n")
        self.assertTrue(self.app.is_dir())
        self.assertFalse(self.resident.exists())
        self.assertFalse(self.daemon.exists())
        self.assertFalse(self.preflight.exists())
        self.assertTrue((self.session_dir / "baseline" / "survey.txt").exists())
        self.assertFalse(Path(str(self.config) + ".early-reset.tmp").exists())
        self.assertFalse(Path(str(self.config) + ".early-reset-restore.tmp").exists())
        self.assertEqual(list(self.tahoe.glob(".cobalt-early-output-probe-*")), [])
        self.assertNotIn("shutdown", self.events())

    def test_non_test_boot_logs_startup_and_leaves_pending(self):
        self.prepare_agent()
        result = self.run_agent(BOOTARGS="cobalt-survey=1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.resident / "pending-session").exists())
        self.assertEqual(self.config.read_bytes(), b"armed\n")
        self.assertIn("capture agent startup", self.log.read_text())
        self.assertFalse(self.trace.exists())

    def test_intended_boot_hash_denial_preserves_private_local_evidence_without_claim_or_reboot(self):
        self.prepare_agent()
        result = self.run_agent(DENY_USB="1")
        self.assertNotEqual(result.returncode, 0)
        evidence = list(self.resident.glob("evidence-*"))
        self.assertEqual(len(evidence), 1, result.stderr + self.log.read_text())
        self.assertTrue((evidence[0] / "early-driver-ioreg.txt").exists())
        self.assertTrue((evidence[0] / "peer-inventory.txt").exists())
        self.assertTrue((evidence[0] / "after-early-test" / "survey.txt").exists())
        self.assertIn("capture_complete=0", (evidence[0] / "incomplete-receipt.txt").read_text())
        self.assertTrue((self.resident / "pending-session").exists())
        self.assertFalse((self.resident / ("consumed-session-" + SESSION)).exists())
        self.assertEqual(self.config.read_bytes(), b"armed\n")
        self.assertNotIn("shutdown", self.events())
        self.assertIn("client:--inspect-peers", self.events())
        self.assertNotIn("client:--run", self.events())
        self.assertNotIn("neither planned", self.log.read_text())

    def test_normal_capture_disarms_before_partial_collection_receipt_and_reboot(self):
        self.prepare_agent()
        result = self.run_agent(DRIVER_MISSING="1", COLLECTOR_EXIT="42")
        self.assertEqual(result.returncode, 0, result.stderr + self.log.read_text())
        self.assertEqual(self.config.read_bytes(), b"base\n")
        self.assertIn(":base", self.events())
        self.assertEqual(self.events().count("collector:"), 1)
        self.assertIn("shutdown", self.events())
        self.assertFalse((self.resident / "pending-session").exists())
        self.assertFalse(self.daemon.exists())
        receipt = (self.resident / ("completion-" + SESSION + ".txt")).read_text()
        self.assertIn("capture_complete=1", receipt)
        self.assertIn("collector_exit=42", receipt)
        self.assertIn("driver_ioreg_exit=7", receipt)
        self.assertTrue((self.session_dir / ("completion-" + SESSION + ".txt")).exists())
        self.assertIn("client:--inspect-peers", self.events())
        self.assertNotIn("client:--run", self.events())


if __name__ == "__main__":
    unittest.main()

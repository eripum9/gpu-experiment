# macOS compile check

The GitHub Actions workflow runs the host-side GPU inspector tests and compiles
`Navi48Bringup.kext` for `x86_64` on GitHub's Intel `macos-15-intel` runner. It
does not load or install the kext, alter an EFI partition, or test GPU hardware.
RX 9060 XT / Navi 44 support remains disabled; a successful job only proves
that this source revision passes its host tests and builds the existing
compile-only target with the pinned inputs described below.

The job runs on pushes, pull requests, and manual dispatch. It requests only
`contents: read`, uses pinned official GitHub actions, cancels an older run for
the same ref, and retains artifacts for seven days. On a public repository,
standard GitHub-hosted runners are free. The job downloads about 2.4 MB of
firmware and license files plus a roughly 2.7 MB MacKernelSDK archive; it does
not clone the full linux-firmware repository. GitHub's runner has its own temporary workspace,
so the laptop's 128 GB drive does not constrain these builds.

## Pinned inputs

`tools/ci/fetch_deps.py` downloads the MacKernelSDK archive from the RDNA4FB
submodule commit `05094e5e88cec7caedbfb35e8449ed0db94bf95b` and verifies the
archive SHA-256 before extracting only `Headers/`, `Library/x86_64/`, and
`LICENSE.txt`. This SDK commit is the submodule recorded by RDNA4FB commit
`5ff69aade9a7feb18bb665040661de33ccfe68ba`.

The script fetches the ten firmware blobs and `LICENSES/LICENSE.amdgpu` from
linux-firmware commit `9a80a04181713da7f8187ec928c15160137f3262`. It checks
both byte length and SHA-256 for each file, first using GitLab's raw endpoint
and then the kernel.org Googlesource mirror. The mirror response is base64
decoded before the same checksum check. Only these ten blobs are written to
the ignored `src/navi48-bringup/firmware/` directory; the license is copied to
that directory as `LICENSE.amdgpu` and included in the packaged artifact.

The workflow also runs `python3 tools/gpu-inspect/build.py all` on every job.
That compiles and runs the host-side inspector tests. It does not establish
graphics acceleration or compatibility with the RX 9060 XT.

## Artifacts

The job uploads the three macOS x86_64 host executables and a tar archive
containing the compiled, ad-hoc-signed kext, build provenance, the project
license/notices, and the AMD firmware license. The archive is for inspection
and download only. Do not treat it as a tested driver or install it on a
machine: it has not been loaded, and the RX 9060 XT remains unsupported.

GitHub-hosted macOS x86_64 capacity is time-limited by GitHub's runner support
policy. The workflow uses `macos-15-intel`, the Intel macOS 15 label documented
by GitHub. If that runner is later retired, the project will need another
Intel macOS build host because the current Makefile targets an x86_64 kext.

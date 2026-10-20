# Native Ubuntu target capture

Run the collector on the desktop containing the RX 9060 XT, booted into
native Ubuntu. A laptop, GitHub runner, or WSL session cannot supply this
card's PCI/IP Discovery data.

The standalone Python 3 script selects AMD PCI `1002:7590` and reads the
existing driver interfaces. It saves one local JSON report and performs no
uploads, installs, GPU resets, PCI configuration writes, firmware changes,
driver binding changes, or debugfs mounts.

The report contains:

- PCI identity, kernel/driver details, VRAM size and VBIOS version.
- All numeric entries in `ip_discovery/die/<die>/<hwid>/<instance>`, including
  IP versions, harvest indicators and register segment bases.
- Target-associated DRM connector status, modes and raw monitor EDIDs.
- When readable, the target driver's cached `amdgpu_discovery` binary,
  encoded as base64 with its size and SHA-256, plus firmware version metadata.

The raw binary is the kernel's existing discovery snapshot, not a generated
substitute. Its checksum and format are validated separately by the inspector
after collection. Ordinary sysfs IP information is already decoded and may
normalize addresses; it is not interchangeable with an original ROM image.

## Run

From a writable working directory in Ubuntu:

```
python3 -c "import urllib.request; urllib.request.urlretrieve('https://raw.githubusercontent.com/eripum9/gpu-experiment/main/tools/gpu-inspect/collect-linux.py', '/tmp/gpu-capture.py')"
sudo python3 /tmp/gpu-capture.py --output ./gpu-capture.json
```

`sudo` permits reading the existing cached discovery file beneath debugfs.
The script never invokes sudo itself and does not read arbitrary debugfs
files. Without sudo it can still save a useful sysfs-only capture, with any
missing raw binary or permission errors recorded explicitly.

Attach `gpu-capture.json` from Ubuntu, or copy it to a location accessible
from Windows before returning there. Actual captures can include monitor
identifiers and must not be committed to the public repository. The default
capture filename is gitignored. The collector refuses to overwrite a report;
choose a different `--output` filename for another run.

If the target is missing, the driver is not `amdgpu`, or required IP blocks
cannot be read, preserve the partial report and terminal error. Do not switch
drivers or change kernel options automatically. Check the installed Ubuntu
kernel and driver initialization first. A missing raw snapshot can simply mean
debugfs is not mounted or that the installed kernel does not expose it.

## References

- [Linux PCI sysfs](https://docs.kernel.org/PCI/sysfs-pci.html)
- [AMDGPU cached discovery and firmware interfaces](https://docs.kernel.org/gpu/amdgpu/debugfs.html)
- [Linux v6.19 IP Discovery sysfs implementation](https://github.com/torvalds/linux/blob/v6.19/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c)

# Read OS-reported hardware metadata only. No PCI configuration, MMIO, ROM
# access, driver installation, firmware updates, or elevation is required.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$issues = [System.Collections.Generic.List[string]]::new()

function Get-OptionalCim {
    param([string] $ClassName)
    try { @(Get-CimInstance -ClassName $ClassName) }
    catch { $issues.Add("Unable to query ${ClassName}: $($_.Exception.Message)") }
}

$controllers = @(Get-OptionalCim Win32_VideoController)
$cpus = @(Get-OptionalCim Win32_Processor)
$boards = @(Get-OptionalCim Win32_BaseBoard)
$memory = @(Get-OptionalCim Win32_PhysicalMemory)
$os = @(Get-OptionalCim Win32_OperatingSystem)
$gpuReports = @(
    foreach ($gpu in $controllers) {
        # Ignore virtual display adapters; retain all physical PCI GPUs.
        if ($gpu.PNPDeviceID -notmatch '^PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') { continue }
        $vendorId = $Matches[1].ToLowerInvariant()
        $deviceId = $Matches[2].ToLowerInvariant()
        $subsystem = $null
        $revision = $null
        if ($gpu.PNPDeviceID -match '&SUBSYS_([0-9A-F]{8})') { $subsystem = $Matches[1].ToLowerInvariant() }
        if ($gpu.PNPDeviceID -match '&REV_([0-9A-F]{2})') { $revision = $Matches[1].ToLowerInvariant() }

        # The WMI AdapterRAM property is a 32-bit value and can truncate large
        # GPUs. Use the driver-reported QWORD when available, never that value.
        $reportedMemory = $null
        $biosVersion = $null
        $classPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
        $enumErrors = @()
        $adapterKeys = @(Get-ChildItem -LiteralPath $classPath -ErrorAction SilentlyContinue -ErrorVariable enumErrors)
        foreach ($adapterKey in $adapterKeys) {
            $props = Get-ItemProperty -LiteralPath $adapterKey.PSPath -ErrorAction SilentlyContinue
            if (-not $props -or -not $props.MatchingDeviceId) { continue }
            # Match the complete hardware ID (including board and revision).
            $pnpHardwareId = ($gpu.PNPDeviceID -split '\\')[1]
            if ($props.MatchingDeviceId -ine "PCI\$pnpHardwareId") { continue }
            $memoryProperty = $props.PSObject.Properties['HardwareInformation.qwMemorySize']
            if ($memoryProperty -and $null -ne $memoryProperty.Value) {
                $reportedMemory = [uint64] $memoryProperty.Value
            }
            $biosProperty = $props.PSObject.Properties['HardwareInformation.BiosString']
            if ($biosProperty -and $biosProperty.Value -is [byte[]]) {
                $biosVersion = [Text.Encoding]::Unicode.GetString($biosProperty.Value).TrimEnd([char]0)
            }
        }
        if ($enumErrors.Count -gt 0) { $issues.Add('Some display registry keys were unreadable; optional metadata may be absent.') }
        [ordered]@{
            name = $gpu.Name
            pci_id = "${vendorId}:${deviceId}"
            subsystem_id = $subsystem
            revision = $revision
            driver_version = $gpu.DriverVersion
            driver_reported_memory_bytes = $reportedMemory
            bios_version = $biosVersion
        }
    }
)

$report = [ordered]@{
    schema_version = 1
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    collection = 'Windows CIM and display driver registry metadata; no direct hardware access'
    cpus = @($cpus | ForEach-Object { [ordered]@{ name = $_.Name; cores = $_.NumberOfCores; logical_processors = $_.NumberOfLogicalProcessors } })
    motherboards = @($boards | ForEach-Object { [ordered]@{ manufacturer = $_.Manufacturer; product = $_.Product } })
    installed_ram_bytes = ($memory | Measure-Object -Property Capacity -Sum).Sum
    windows = @($os | ForEach-Object { [ordered]@{ name = $_.Caption; version = $_.Version; build = $_.BuildNumber } })
    gpus = $gpuReports
    missing_for_port = @('Full saved ROM containing IP Discovery, or a Linux IP Discovery sysfs capture', 'Per-block IP versions and register segment bases', 'Target display topology and monitor EDIDs')
    issues = @($issues)
}

# Refuse overwrite so repeated collections do not silently replace evidence.
$absoluteOutput = [IO.Path]::GetFullPath($OutputPath)
$jsonBytes = [Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
$stream = [IO.File]::Open($absoluteOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try { $stream.Write($jsonBytes, 0, $jsonBytes.Length) } finally { $stream.Dispose() }
Write-Output "Saved hardware metadata: $absoluteOutput"

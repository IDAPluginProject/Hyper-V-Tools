<#
.SYNOPSIS
    Secure Kernel IUM Debugging Tool — Minimal symbol-based version.

.DESCRIPTION
    Enables IUM (Isolated User Mode) process debugging by patching securekernel's
    SkpsIsProcessDebuggingEnabled check via Hyper-V live memory introspection.

    How it works (high-level):
      1. Reads the securekernel.exe image from VTL1 via page table walk
      2. Resolves IumInvokeSecureService and SkpsIsProcessDebuggingEnabled
         symbols using Hvlib SDK (Get-HvlibSymbolAddressDirect)
      3. Disassembles IumInvokeSecureService with Capstone to find the
         error-code block that returns STATUS_ACCESS_DENIED (0xC0000022)
      4. Scans physical memory for the page containing the "ret" instruction
         to determine the real physical location
      5. Writes a PAUSE+LOOP trap (F3 90 EB FC C3) at that "ret" to catch
         a VTL1 CPU in securekernel — this reveals the true runtime base
      6. Once a VP is trapped, reverts the trap and overwrites the
         error-code block with NOPs, effectively enabling IUM debugging

    Based on cbwang505's hvsecurekernel C# tool, rewritten in PowerShell
    using Hvlib SDK primitives instead of raw DeviceIoControl/P/Invoke.

    Requires:
      - Hvlib module v1.5.0+ (symbol and partition config support)
      - Hvlib_aux module (Capstone disassembly wrapper)
      - Capstone engine (pip install capstone)
      - hvmm driver loaded (LiveCloudKd)

.PARAMETER DllPath
    Path to hvlibdotnet.dll. If omitted, reads from Hvlib-Config.json
    or falls back to C:\Distr\LiveCloudKd_public\hvlibdotnet.dll.

.PARAMETER VmName
    Name of the target VM (as shown in Hyper-V Manager).
    Default: "Windows Server 2025".

.PARAMETER CapstoneDllPath
    Path to capstone.dll. Auto-detected from Python site-packages if omitted.

.PARAMETER ScanStartAddress
    Starting physical address for the page signature scan. Default: 0x600000.
    Increase if securekernel is mapped at higher addresses.

.PARAMETER DryRun
    Perform analysis only — do not write any patches to VM memory.

.PARAMETER Restore
    Restore mode: read the backup file and write original bytes back to VM memory,
    reverting the IUM debug patch. Requires a valid backup file created during patching.

.PARAMETER BackupPath
    Path to the backup JSON file. Default: securekernel_patch_backup.json in the script directory.
    Created automatically during patching; required for -Restore.

.EXAMPLE
    # Basic usage with defaults
    .\Invoke-SecurekernelIUMDebug-Lite.ps1 -VmName "Windows Server 2025"

.EXAMPLE
    # Dry run to inspect analysis without patching
    .\Invoke-SecurekernelIUMDebug-Lite.ps1 -VmName "MyVM" -DryRun

.EXAMPLE
    # Restore original securekernel bytes from backup
    .\Invoke-SecurekernelIUMDebug-Lite.ps1 -Restore

.EXAMPLE
    # Restore from a custom backup file
    .\Invoke-SecurekernelIUMDebug-Lite.ps1 -Restore -BackupPath "C:\backups\sk_backup.json"

.EXAMPLE
    # Custom DLL path
    .\Invoke-SecurekernelIUMDebug-Lite.ps1 -DllPath "D:\tools\hvlibdotnet.dll" -VmName "TestVM"

.LINK
    https://github.com/gerhart01/Hyper-V-Tools
#>

param(
    [string]$DllPath,
    [string]$VmName,
    [string]$CapstoneDllPath,
    [uint64]$ScanStartAddress = 0x600000,
    [switch]$DryRun,
    [switch]$Restore,
    [string]$BackupPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Default backup file path
if (-not $BackupPath) {
    $BackupPath = Join-Path $PSScriptRoot "securekernel_patch_backup.json"
}

# Import auxiliary module (Capstone disassembly functions)
# Hvlib_aux.psm1 is located alongside Hvlib.psm1 in the Hvlib module directory
if (-not (Get-Command Initialize-Capstone -ErrorAction SilentlyContinue)) {
    $hvlibAuxPath = Join-Path (Split-Path (Get-Module Hvlib -ListAvailable | Select-Object -First 1).Path) "Hvlib_aux.psd1"
    if (Test-Path $hvlibAuxPath) {
        Import-Module $hvlibAuxPath -ErrorAction Stop
    } else {
        Import-Module Hvlib_aux -ErrorAction Stop
    }
}


# ==============================================================================
# CONSTANTS
# ==============================================================================

# Trap code: PAUSE; JMP $-2; RET — creates an infinite loop that a VP will
# spin on, allowing us to detect it via register polling
$PATCH_CODE  = [byte[]]@(0xF3, 0x90, 0xEB, 0xFC, 0xC3)

# Revert code: 5x RET — safe landing pad to restore original behavior
$REVERT_CODE = [byte[]]@(0xC3, 0xC3, 0xC3, 0xC3, 0xC3)

$PAGE_SIZE = 0x1000

# Hyper-V register codes for VP register access
$HvX64RegisterRip = 0x00020010
$HvX64RegisterCr3 = 0x00040002

# HVDD_INFORMATION_CLASS enum values
$HvddPartitionId = 2
$HvddKernelBase  = 11
$HvddNumberOfCPU = 8

# Virtual Trust Level 1 (Secure Kernel)
$Vtl1 = 1

# Console color scheme
$COLOR_INFO    = 'Cyan'
$COLOR_SUCCESS = 'Green'
$COLOR_WARN    = 'Yellow'
$COLOR_ERROR   = 'Red'
$COLOR_DEBUG   = 'DarkGray'


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

function Format-HexDump {
    <#
    .SYNOPSIS
        Print a hex dump of a byte array (address + hex + ASCII).
    #>
    param(
        [byte[]]$Bytes,
        [uint64]$BaseAddress = 0,
        [int]$BytesPerLine = 16
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        Write-Host "<empty>" -ForegroundColor $COLOR_WARN
        return
    }

    for ($i = 0; $i -lt $Bytes.Length; $i += $BytesPerLine) {
        $hex   = ""
        $ascii = ""

        for ($j = 0; $j -lt $BytesPerLine; $j++) {
            if (($i + $j) -lt $Bytes.Length) {
                $b = $Bytes[$i + $j]
                $hex   += "{0:X2} " -f $b
                $ascii += if ($b -ge 0x20 -and $b -le 0x7E) { [char]$b } else { '.' }
            }
            else {
                $hex   += "   "
                $ascii += " "
            }

            # Extra space between 8th and 9th byte for readability
            if ($j -eq 7) { $hex += " " }
        }

        Write-Host ("{0:X16}  {1} {2}" -f ($BaseAddress + $i), $hex, $ascii)
    }
}


function Compare-ByteArrays {
    <#
    .SYNOPSIS
        Compare a pattern against a region inside a source byte array.
        Returns $true if all bytes match.
    #>
    param(
        [byte[]]$Source,
        [byte[]]$Pattern,
        [int]$SourceOffset = 0
    )

    if ($null -eq $Source -or $null -eq $Pattern) { return $false }
    if (($SourceOffset + $Pattern.Length) -gt $Source.Length) { return $false }

    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if ($Source[$SourceOffset + $i] -ne $Pattern[$i]) { return $false }
    }

    return $true
}


function Read-PhysicalUInt64 {
    <#
    .SYNOPSIS
        Read a single UInt64 value from guest physical memory.
    #>
    param(
        [uint64]$Handle,
        [uint64]$Address
    )

    $data = Get-HvlibVmPhysicalMemory -prtnHandle $Handle -start_position $Address -size 8

    if ($null -eq $data -or $data.Length -lt 8) { return [uint64]0 }

    return [BitConverter]::ToUInt64($data, 0)
}


function Resolve-PageTableAddress {
    <#
    .SYNOPSIS
        Walk the 4-level x64 page table (PML4 → PDPT → PD → PT) to translate
        a guest virtual address to a guest physical address.

    .DESCRIPTION
        Supports 4KB, 2MB, and 1GB pages. Returns 0 if any level fails.
        This is needed because securekernel (VTL1) pages are not accessible
        via standard virtual memory read — we must manually walk its CR3.
    #>
    param(
        [uint64]$Handle,
        [uint64]$DirectoryTableBase,
        [uint64]$VirtualAddress,
        [switch]$Quiet
    )

    # Level 4: PML4E
    $pml4Idx  = ($VirtualAddress -shr 39) -band 0x1FF
    $pml4eAddr = $DirectoryTableBase + [uint64]($pml4Idx * 8)
    $pml4e    = Read-PhysicalUInt64 -Handle $Handle -Address $pml4eAddr
    if ($pml4e -eq 0) { return [uint64]0 }

    # Level 3: PDPTE
    $pdptIdx   = ($VirtualAddress -shr 30) -band 0x1FF
    $pdpteAddr = ($pml4e -band 0xFFFFFFFFFFF000) + [uint64]($pdptIdx * 8)
    $pdpte     = Read-PhysicalUInt64 -Handle $Handle -Address $pdpteAddr
    if ($pdpte -eq 0) { return [uint64]0 }

    # 1GB huge page? (PS bit set)
    if (($pdpte -band (1 -shl 7)) -ne 0) {
        return ($pdpte -band 0xFFFFFC0000000) + ($VirtualAddress -band 0x3FFFFFFF)
    }

    # Level 2: PDE
    $pdIdx   = ($VirtualAddress -shr 21) -band 0x1FF
    $pdeAddr = ($pdpte -band 0xFFFFFFFFFF000) + [uint64]($pdIdx * 8)
    $pde     = Read-PhysicalUInt64 -Handle $Handle -Address $pdeAddr
    if ($pde -eq 0) { return [uint64]0 }

    # 2MB large page? (PS bit set)
    if (($pde -band (1 -shl 7)) -ne 0) {
        return ($pde -band 0xFFFFFFFE00000) + ($VirtualAddress -band 0x1FFFFF)
    }

    # Level 1: PTE (standard 4KB page)
    $ptIdx   = ($VirtualAddress -shr 12) -band 0x1FF
    $pteAddr = ($pde -band 0xFFFFFFFFFF000) + [uint64]($ptIdx * 8)
    $pte     = Read-PhysicalUInt64 -Handle $Handle -Address $pteAddr
    if ($pte -eq 0) { return [uint64]0 }

    return ($pte -band 0xFFFFFFFFFF000) + ($VirtualAddress -band 0xFFF)
}


function Read-SecurekernelVirtualMemory {
    <#
    .SYNOPSIS
        Read a contiguous region of securekernel virtual memory by manually
        walking VTL1 page tables (page-by-page, handling page boundaries).
    #>
    param(
        [uint64]$Handle,
        [uint64]$CR3,
        [uint64]$VirtualAddress,
        [int]$Size
    )

    $result    = [byte[]]::new($Size)
    $offset    = 0
    $remaining = $Size

    while ($remaining -gt 0) {
        $currentVA  = $VirtualAddress + [uint64]$offset
        $pageOffset = [int]($currentVA -band 0xFFF)
        $chunkSize  = [Math]::Min($remaining, $PAGE_SIZE - $pageOffset)

        # Translate VA → PA via VTL1 page table
        $physAddr = Resolve-PageTableAddress `
            -Handle $Handle `
            -DirectoryTableBase $CR3 `
            -VirtualAddress $currentVA `
            -Quiet

        if ($physAddr -eq 0) {
            Write-Warning ("Failed to translate VA 0x{0:X16}" -f $currentVA)
            return $null
        }

        # Read physical memory at the translated address
        $data = Get-HvlibVmPhysicalMemory `
            -prtnHandle $Handle `
            -start_position $physAddr `
            -size $chunkSize

        if ($null -eq $data) {
            Write-Warning ("Failed to read phys 0x{0:X16}" -f $physAddr)
            return $null
        }

        [Array]::Copy($data, 0, $result, $offset, $chunkSize)
        $offset    += $chunkSize
        $remaining -= $chunkSize
    }

    return $result
}


# ==============================================================================
# VTL PROTECTION MODIFICATION
# ==============================================================================

function Invoke-HvlibModifyVtlProtection {
    <#
    .SYNOPSIS
        Modify VTL protection for a physical page via HvModifyVtlProtectionMask
        hypercall (0x000C). Makes the page writable from VTL0 so we can patch
        securekernel memory.

    .DESCRIPTION
        Calls [Hvlibdotnet.Hvlib]::ModifyVtlProtection() which internally
        invokes SdkInvokeHypercall with the correct input structure.
        Return value 0 = success.
    #>
    param(
        [uint64]$PartitionId,
        [uint64]$PhysicalAddress
    )

    $pageAligned = $PhysicalAddress -band 0xFFFFFFFFFFFFF000
    $result = [Hvlibdotnet.Hvlib]::ModifyVtlProtection($PartitionId, $pageAligned)

    if ($result -eq 0) {
        Write-Host ("  VTL protection modified for 0x{0:X16}" -f $pageAligned) -ForegroundColor $COLOR_SUCCESS
        return $true
    }

    Write-Host ("  VTL protection hypercall result: 0x{0:X}" -f $result) -ForegroundColor $COLOR_WARN
    return ($result -ne 0xFFFFFFFF -and $result -ne 0xFFFFFFFE)
}


function Invoke-HvModifyVtlProtectionMask {
    <#
    .SYNOPSIS
        Convenience alias for Invoke-HvlibModifyVtlProtection (compatibility).
    #>
    param(
        [uint64]$PartitionId,
        [uint64]$PhysicalAddress
    )

    return Invoke-HvlibModifyVtlProtection -PartitionId $PartitionId -PhysicalAddress $PhysicalAddress
}


# ==============================================================================
# BACKUP / RESTORE
# ==============================================================================

function Save-PatchBackup {
    <#
    .SYNOPSIS
        Save original bytes and patch metadata to a JSON backup file.
    #>
    param(
        [string]$Path,
        [uint64]$SecurekernelBase,
        [uint64]$PatchRVA,
        [int]$PatchLength,
        [byte[]]$OriginalBytes,
        [byte[]]$PatchedBytes,
        [uint64]$PatchPhysicalAddress,
        [uint64]$RetRVA
    )

    $backup = [ordered]@{
        Version              = 1
        Timestamp            = (Get-Date -Format 'o')
        SecurekernelBase     = "0x{0:X}" -f $SecurekernelBase
        PatchRVA             = "0x{0:X}" -f $PatchRVA
        PatchLength          = $PatchLength
        OriginalBytesHex     = ($OriginalBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
        PatchedBytesHex      = ($PatchedBytes  | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
        PatchPhysicalAddress = "0x{0:X}" -f $PatchPhysicalAddress
        RetRVA               = "0x{0:X}" -f $RetRVA
    }

    $backup | ConvertTo-Json -Depth 3 | Set-Content -Path $Path -Encoding UTF8
    Write-Host ("  Backup saved: {0}" -f $Path) -ForegroundColor $COLOR_SUCCESS
}


function Read-PatchBackup {
    <#
    .SYNOPSIS
        Read patch backup from JSON file and parse hex fields.
    .OUTPUTS
        PSCustomObject with parsed fields, or $null if file is invalid.
    #>
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Error "Backup file not found: $Path"
        return $null
    }

    $json = Get-Content $Path -Raw | ConvertFrom-Json
    if ($json.Version -ne 1) {
        Write-Error "Unsupported backup version: $($json.Version)"
        return $null
    }

    $origBytes = [byte[]]($json.OriginalBytesHex -split ' ' | ForEach-Object { [Convert]::ToByte($_, 16) })
    $patchBytes = [byte[]]($json.PatchedBytesHex -split ' ' | ForEach-Object { [Convert]::ToByte($_, 16) })

    [PSCustomObject]@{
        Timestamp            = $json.Timestamp
        SecurekernelBase     = [uint64]::Parse($json.SecurekernelBase.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
        PatchRVA             = [uint64]::Parse($json.PatchRVA.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
        PatchLength          = [int]$json.PatchLength
        OriginalBytes        = $origBytes
        PatchedBytes         = $patchBytes
        PatchPhysicalAddress = [uint64]::Parse($json.PatchPhysicalAddress.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
        RetRVA               = [uint64]::Parse($json.RetRVA.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
    }
}


# ==============================================================================
# SYMBOL ADDRESS RESOLVER
# ==============================================================================

function Resolve-AddressToSymbol {
    <#
    .SYNOPSIS
        Given an RVA, find the nearest symbol whose address is <= the RVA.
        This tells us which function "contains" the given address.
    .PARAMETER AllSymbols
        Sorted array of PSCustomObjects with .Name and .AddressUInt64 properties.
    .PARAMETER RVA
        Relative virtual address to resolve.
    .PARAMETER SecurekernelBase
        Base VA of securekernel (used to compute RVA from symbol VA).
    .OUTPUTS
        PSCustomObject with SymbolName, SymbolRVA, Offset (RVA - SymbolRVA), or $null.
    #>
    param(
        [object[]]$AllSymbols,
        [uint64]$RVA,
        [uint64]$SecurekernelBase
    )

    $targetVA = $SecurekernelBase + $RVA
    $bestSym  = $null
    $bestDist = [uint64]::MaxValue

    foreach ($sym in $AllSymbols) {
        $symVA = $sym.AddressUInt64
        if ($symVA -le $targetVA) {
            $dist = $targetVA - $symVA
            if ($dist -lt $bestDist) {
                $bestDist = $dist
                $bestSym  = $sym
            }
        }
    }

    if ($null -eq $bestSym) { return $null }

    return [PSCustomObject]@{
        SymbolName = $bestSym.Name
        SymbolRVA  = [uint64]($bestSym.AddressUInt64 - $SecurekernelBase)
        Offset     = [uint64]$bestDist
    }
}


function Show-PatchAddressContext {
    <#
    .SYNOPSIS
        Enumerate all securekernel symbols and show which functions contain
        the patch address and the RET address.
    #>
    param(
        [uint64]$PartitionHandle,
        [uint64]$PatchRVA,
        [uint64]$RetRVA,
        [uint64]$SecurekernelBase
    )

    Write-Host "`n--- Verifying patch location via symbol table ---" -ForegroundColor $COLOR_INFO

    # Get all symbols — try "securekernel" first (works faster than "securekernel.exe")
    $allSyms = $null
    foreach ($drvName in @("securekernel", "securekernel.exe")) {
        $allSyms = Get-HvlibAllSymbols -PartitionHandle $PartitionHandle -DriverName $drvName
        if ($null -ne $allSyms -and $allSyms.Count -gt 0) {
            Write-Host ("  Loaded {0} symbols from '{1}'" -f $allSyms.Count, $drvName) -ForegroundColor $COLOR_DEBUG
            break
        }
    }

    if ($null -eq $allSyms -or $allSyms.Count -eq 0) {
        Write-Warning "  Cannot load symbol table — skipping address verification"
        return
    }

    # Parse hex addresses to UInt64 and normalize to current SecurekernelBase.
    # The SDK may return addresses rebased to the live module base OR to a stale/cached
    # base. Detect which case by checking the first symbol's offset from SecurekernelBase.
    # If addresses are wildly outside the image, compute an enumBase offset and rebase.
    # Detect enum base by looking for IumInvokeSecureService (known RVA 0x13B20).
    # If enum addresses use a different base than runtime SecurekernelBase, rebase them.
    $iumRef = $allSyms | Where-Object { $_.Name -eq "IumInvokeSecureService" } | Select-Object -First 1
    $enumBase = $SecurekernelBase  # assume same base unless proven otherwise
    if ($iumRef) {
        $iumEnumAddr = [uint64]::Parse($iumRef.Address.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
        $enumBase = $iumEnumAddr - [uint64]0x13B20
        if ($enumBase -ne $SecurekernelBase) {
            Write-Host ("  Enum base mismatch: enum=0x{0:X}, runtime=0x{1:X}, rebasing" -f $enumBase, $SecurekernelBase) -ForegroundColor $COLOR_DEBUG
        }
    }

    $parsed = $allSyms | ForEach-Object {
        $va = [uint64]::Parse($_.Address.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
        $rva = $va - $enumBase
        [PSCustomObject]@{ Name = $_.Name; AddressUInt64 = ($SecurekernelBase + $rva) }
    } | Sort-Object AddressUInt64

    # Resolve patch address
    $patchSym = Resolve-AddressToSymbol -AllSymbols $parsed -RVA $PatchRVA -SecurekernelBase $SecurekernelBase
    if ($patchSym) {
        Write-Host ("  Patch RVA 0x{0:X} is inside: {1}+0x{2:X}  (function RVA 0x{3:X})" -f `
            $PatchRVA, $patchSym.SymbolName, $patchSym.Offset, $patchSym.SymbolRVA) -ForegroundColor $COLOR_SUCCESS
    } else {
        Write-Host ("  Patch RVA 0x{0:X}: no matching symbol found" -f $PatchRVA) -ForegroundColor $COLOR_WARN
    }

    # Resolve RET address
    $retSym = Resolve-AddressToSymbol -AllSymbols $parsed -RVA $RetRVA -SecurekernelBase $SecurekernelBase
    if ($retSym) {
        Write-Host ("  RET   RVA 0x{0:X} is inside: {1}+0x{2:X}  (function RVA 0x{3:X})" -f `
            $RetRVA, $retSym.SymbolName, $retSym.Offset, $retSym.SymbolRVA) -ForegroundColor $COLOR_SUCCESS
    } else {
        Write-Host ("  RET   RVA 0x{0:X}: no matching symbol found" -f $RetRVA) -ForegroundColor $COLOR_WARN
    }
}


# ==============================================================================
# SYMBOL-BASED PATCH FINDER
# ==============================================================================

function Find-PatchContext {
    <#
    .SYNOPSIS
        Locate the exact bytes to patch inside IumInvokeSecureService.

    .DESCRIPTION
        Strategy:
          1. Resolve IumInvokeSecureService VA via symbols
          2. Resolve SkpsIsProcessDebuggingEnabled VA via symbols
          3. Disassemble IumInvokeSecureService looking for:
             - LEA reg, [rip+disp] that points to SkpsIsProcessDebuggingEnabled
             - After the LEA, find a JMP whose target contains either:
               a) A NOP sled (0x90 x N) → patch already applied
               b) STATUS_ACCESS_DENIED (0xC0000022) + short JMP (0xEB) → patch target
          4. Find the nearest RET after the patch point — this will be used
             as the trap location and page signature anchor

    .OUTPUTS
        PSCustomObject with:
          - PatchOffset    : RVA of the error-code block to NOP out
          - PatchLen       : Number of bytes to overwrite with NOPs
          - RetOffset      : RVA of the RET instruction (trap target)
          - CheckPage      : Byte signature of the page containing RET
          - AlreadyPatched : $true if NOP sled already present
    #>
    param(
        [uint64]$PartitionHandle,
        [byte[]]$ImageBytes,
        [uint64]$SecurekernelBase
    )

    # ---- Step 1: Resolve symbol addresses ----
    # Try direct lookup first (SdkSymGetSymbolAddress2), then fall back
    # to full enumeration (GetAllSymbolsForModule) if direct fails.

    $iumVA  = [uint64]0
    $skpsVA = [uint64]0

    # --- Try direct lookup ---
    $iumVA = Get-HvlibSymbolAddressDirect `
        -PartitionHandle $PartitionHandle `
        -SymbolFullName "securekernel!IumInvokeSecureService" `
        -ErrorAction SilentlyContinue 3>$null

    if ($iumVA -ne 0) {
        $skpsVA = Get-HvlibSymbolAddressDirect `
            -PartitionHandle $PartitionHandle `
            -SymbolFullName "securekernel!SkpsIsProcessDebuggingEnabled" `
            -ErrorAction SilentlyContinue 3>$null
    }

    # --- Fallback: full enumeration for missing symbols ---
    if ($iumVA -eq 0 -or $skpsVA -eq 0) {
        $missing = @()
        if ($iumVA  -eq 0) { $missing += "IumInvokeSecureService" }
        if ($skpsVA -eq 0) { $missing += "SkpsIsProcessDebuggingEnabled" }
        Write-Host ("  Direct lookup missed: {0}. Trying full enumeration..." -f ($missing -join ', ')) -ForegroundColor $COLOR_WARN

        $driverName = "securekernel"
        $allSyms = Get-HvlibAllSymbols -PartitionHandle $PartitionHandle -DriverName $driverName

        if ($null -eq $allSyms -or $allSyms.Count -eq 0) {
            # Try alternate name
            $altName = if ($driverName -eq "securekernel.exe") { "securekernel" } else { "securekernel.exe" }
            $allSyms = Get-HvlibAllSymbols -PartitionHandle $PartitionHandle -DriverName $altName
        }

        if ($null -ne $allSyms -and $allSyms.Count -gt 0) {
            Write-Host ("  Enumerated {0} symbols" -f $allSyms.Count) -ForegroundColor $COLOR_SUCCESS

            # Enum addresses may use a stale base. Detect enumBase from
            # IumInvokeSecureService (known RVA 0x13B20) and rebase to runtime.
            $iumRef = $allSyms | Where-Object { $_.Name -eq "IumInvokeSecureService" } | Select-Object -First 1
            $enumBase = $SecurekernelBase
            if ($iumRef) {
                $iumEnumAddr = [uint64]::Parse($iumRef.Address.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
                $enumBase = $iumEnumAddr - [uint64]0x13B20
                if ($enumBase -ne $SecurekernelBase) {
                    Write-Host ("  Enum base mismatch: enum=0x{0:X}, runtime=0x{1:X}, rebasing" -f $enumBase, $SecurekernelBase) -ForegroundColor $COLOR_WARN
                }
            }

            if ($iumVA -eq 0 -and $iumRef) {
                $iumEnumAddr = [uint64]::Parse($iumRef.Address.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
                $iumVA = $SecurekernelBase + ($iumEnumAddr - $enumBase)
                Write-Host ("  securekernel!IumInvokeSecureService : 0x{0:X}" -f $iumVA) -ForegroundColor $COLOR_SUCCESS
            }
            if ($skpsVA -eq 0) {
                $skpsSym = $allSyms | Where-Object { $_.Name -eq "SkpsIsProcessDebuggingEnabled" } | Select-Object -First 1
                if ($skpsSym) {
                    $skpsEnumAddr = [uint64]::Parse($skpsSym.Address.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
                    $skpsVA = $SecurekernelBase + ($skpsEnumAddr - $enumBase)
                    Write-Host ("  securekernel!SkpsIsProcessDebuggingEnabled : 0x{0:X}" -f $skpsVA) -ForegroundColor $COLOR_SUCCESS
                }
            }
        }
    }

    if ($iumVA -eq 0) {
        Write-Error "Symbol IumInvokeSecureService not found via any method"
        return $null
    }

    # Convert VAs to RVAs (relative to securekernel base)
    # Validate that addresses are within the image range to catch stale symbol data
    $imageSize = [uint64]$ImageBytes.Length
    if ($iumVA -lt $SecurekernelBase -or ($iumVA - $SecurekernelBase) -ge $imageSize) {
        Write-Warning ("  IumInvokeSecureService VA 0x{0:X} is outside image [0x{1:X}..0x{2:X}] — symbol data may be stale" -f $iumVA, $SecurekernelBase, ($SecurekernelBase + $imageSize))
        Write-Error "Symbol address out of range — try restarting VM or clearing symbol cache"
        return $null
    }

    $iumRVA  = [uint32]($iumVA  - $SecurekernelBase)
    $skpsRVA = [uint32]0
    if ($skpsVA -ne 0) {
        if ($skpsVA -ge $SecurekernelBase -and ($skpsVA - $SecurekernelBase) -lt $imageSize) {
            $skpsRVA = [uint32]($skpsVA - $SecurekernelBase)
        } else {
            Write-Warning ("  SkpsIsProcessDebuggingEnabled VA 0x{0:X} outside image — ignoring, will scan by pattern" -f $skpsVA)
            $skpsVA = [uint64]0
        }
    }

    Write-Host ("  IumInvokeSecureService        RVA => 0x{0:X}" -f $iumRVA)  -ForegroundColor $COLOR_SUCCESS
    if ($skpsRVA -ne 0) {
        Write-Host ("  SkpsIsProcessDebuggingEnabled  RVA => 0x{0:X}" -f $skpsRVA) -ForegroundColor $COLOR_SUCCESS
    } else {
        Write-Host "  SkpsIsProcessDebuggingEnabled not in symbols — will scan by code pattern" -ForegroundColor $COLOR_WARN
    }

    # ---- Step 2: Disassemble IumInvokeSecureService ----

    $readLen   = [Math]::Min(0x8000, $ImageBytes.Length - $iumRVA)
    $dumpBytes = [byte[]]::new($readLen)
    [Array]::Copy($ImageBytes, $iumRVA, $dumpBytes, 0, $readLen)

    $instructions = Invoke-CapstoneDisasm -Bytes $dumpBytes -BaseAddress ([uint64]$iumRVA)

    # ---- Step 3: Find the LEA referencing SkpsIsProcessDebuggingEnabled ----
    # If skpsRVA is known, match LEA target exactly.
    # If skpsRVA is 0 (symbol not found), match any LEA [rip+X] followed by
    # the STATUS_ACCESS_DENIED (0xC0000022) pattern — there is only one such
    # sequence in IumInvokeSecureService.

    [int64]$patchOffset = 0
    [int]$patchLen      = 0
    $alreadyPatched     = $false
    $foundRef           = $false
    $jdx                = 0

    for ($idx = 0; $idx -lt $instructions.Count; $idx++) {
        $insn = $instructions[$idx]

        # We're looking for: lea reg, [rip + offset_to_SkpsIsProcessDebuggingEnabled]
        if ($insn.Mnemonic -ne 'lea') { continue }
        $leaTarget = Get-CapstoneLeaRipTarget -Insn $insn
        if ($leaTarget -eq 0) { continue }
        # If we know skpsRVA, filter by exact match; otherwise accept any LEA [rip+X]
        if ($skpsRVA -ne 0 -and $leaTarget -ne $skpsRVA) { continue }

        # ---- Step 3a: Walk forward to find the JMP leading to 0xC0000022 error block ----
        # Pattern: LEA rcx, [SkpsIsProcessDebuggingEnabled] → CALL → test → Jcc → ... → JMP to error block
        # We look for any JMP within ~40 instructions whose target contains STATUS_ACCESS_DENIED

        $candidateFound = $false
        for ($jdx = $idx + 1; $jdx -lt [Math]::Min($idx + 40, $instructions.Count); $jdx++) {
            $jInsn = $instructions[$jdx]

            # We only care about unconditional JMP
            if ($jInsn.Mnemonic -ne 'jmp') { continue }

            $jTarget     = Get-CapstoneBranchTarget -Insn $jInsn
            $fetchOffset = [int]($jTarget - [uint64]$iumRVA)

            if ($fetchOffset -le 0 -or $fetchOffset -ge $readLen) { continue }

            # ---- Check 1: NOP sled → patch was already applied ----
            if ($dumpBytes[$fetchOffset] -eq 0x90) {
                $nopCount = 0
                for ($n = $fetchOffset; $n -lt $readLen -and $dumpBytes[$n] -eq 0x90; $n++) {
                    $nopCount++
                }
                if ($nopCount -ge 2) {
                    $patchOffset   = [int64]$iumRVA + $fetchOffset
                    $patchLen      = $nopCount
                    $alreadyPatched = $true
                    Write-Host ("  NOP sled at 0x{0:X} (len 0x{1:X}) - ALREADY PATCHED" -f `
                        $patchOffset, $nopCount) -ForegroundColor $COLOR_WARN
                    break
                }
            }

            # ---- Check 2: STATUS_ACCESS_DENIED (0xC0000022) + short JMP ----
            # The error block looks like:
            #   mov eax, 0xC0000022   ; STATUS_ACCESS_DENIED
            #   jmp <epilog>          ; short jump (0xEB xx)
            $errorPattern = [byte[]]@(0x22, 0x00, 0x00, 0xC0)  # little-endian 0xC0000022
            $errorFound   = $false

            for ($i = 0; $i -lt 0x20; $i++) {
                # Look for the STATUS_ACCESS_DENIED constant
                if (($fetchOffset + $i + 4) -le $dumpBytes.Length) {
                    if (Compare-ByteArrays -Source $dumpBytes -Pattern $errorPattern -SourceOffset ($fetchOffset + $i)) {
                        $errorFound = $true
                    }
                }

                # After finding the constant, look for a short JMP (0xEB) — end of the block
                if ($errorFound -and ($fetchOffset + $i) -lt $dumpBytes.Length -and $dumpBytes[$fetchOffset + $i] -eq 0xEB) {
                    $patchOffset = [int64]$iumRVA + $fetchOffset
                    $patchLen    = $i + 2   # include the JMP + its offset byte
                    Write-Host ("  Patch target => RVA 0x{0:X}, length 0x{1:X}" -f `
                        $patchOffset, $patchLen) -ForegroundColor $COLOR_SUCCESS
                    break
                }
            }

            if ($patchLen -gt 0 -or $alreadyPatched) {
                $candidateFound = $true
                break
            }
        }

        # If this LEA led to a valid patch target, we're done
        if ($candidateFound) {
            Write-Host ("  Found LEA -> SkpsIsProcessDebuggingEnabled at RVA 0x{0:X}" -f `
                ([uint64]$iumRVA + $insn.Offset)) -ForegroundColor $COLOR_SUCCESS
            $foundRef = $true
            break
        }

        # If skpsRVA was known (exact match), this LEA was the right one but pattern failed
        if ($skpsRVA -ne 0) {
            $foundRef = $true
            break
        }

        # skpsRVA == 0: this LEA wasn't the one, try next LEA
    }

    if (-not $foundRef) {
        Write-Error "No LEA referencing SkpsIsProcessDebuggingEnabled found in IumInvokeSecureService"
        return $null
    }

    # ---- Step 4: Find the nearest RET — used as trap anchor and page signature ----

    $startIdx = if ($jdx -gt 0) { $jdx } else { $idx }

    for ($ridx = $startIdx; $ridx -lt $instructions.Count; $ridx++) {
        $rInsn = $instructions[$ridx]

        if ($rInsn.Mnemonic -ne 'ret') { continue }

        $retRVA = [uint64]$iumRVA + $rInsn.Offset

        # Extract the page-aligned portion of the code around RET
        # to use as a unique byte signature for physical memory scanning
        $retPageOffset  = [int]($retRVA -band 0xFFF)
        $pageStartInBuf = [int64]$rInsn.Offset - [int64]$retPageOffset
        if ($pageStartInBuf -lt 0) { $pageStartInBuf = 0 }

        return [PSCustomObject]@{
            PatchOffset    = [uint64]$patchOffset
            PatchLen       = $patchLen
            RetOffset      = [uint64]$retRVA
            CheckPage      = [byte[]]$dumpBytes[[int]$pageStartInBuf..([int]$rInsn.Offset - 1)]
            AlreadyPatched = $alreadyPatched
        }
    }

    # Fallback: no RET found (should not happen in practice)
    return [PSCustomObject]@{
        PatchOffset    = [uint64]$patchOffset
        PatchLen       = $patchLen
        RetOffset      = [uint64]0
        CheckPage      = [byte[]]@()
        AlreadyPatched = $alreadyPatched
    }
}


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

Write-Host @"

  ================================================================
  Secure Kernel IUM Debug Tool (Lite - symbol-based)
  Requires: Hvlib v1.5.0+, Hvlib_aux, Capstone, hvmm driver
  ================================================================

"@ -ForegroundColor $COLOR_INFO


# --- Load configuration (JSON > parameter > defaults) ---

if (-not $DllPath) {
    $cfgPath = Join-Path $PSScriptRoot "Hvlib-Config.json"
    if (Test-Path $cfgPath) {
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        if ($cfg.DllPath)                  { $DllPath = $cfg.DllPath }
        if (-not $VmName -and $cfg.VmName) { $VmName  = $cfg.VmName }
    }
    if (-not $DllPath) {
        $DllPath = "C:\Distr\LiveCloudKd_public\hvlibdotnet.dll"
    }
}
if (-not $VmName) { $VmName = "Windows Server 2025" }

Write-Host "DLL:  $DllPath"  -ForegroundColor $COLOR_INFO
Write-Host "VM:   $VmName"   -ForegroundColor $COLOR_INFO
Write-Host ""


# --- Initialize Hvlib and connect to VM ---

Get-Hvlib -path_to_dll $DllPath | Out-Null

$vmHandle = Get-HvlibPartition -VmName $VmName
if ($null -eq $vmHandle -or $vmHandle -eq 0) {
    Write-Error "VM '$VmName' not found"
    return
}

# Switch WriteMethod from WinHv (default, respects VTL protections)
# to HvmmDrvInternal (bypasses VTL, required for writing to VTL1 pages)
Write-Host ("Current WriteMethod: {0}" -f ([Hvlibdotnet.Hvlib]::GetWriteMethod())) -ForegroundColor $COLOR_DEBUG
Set-HvlibWriteMethod -PartitionHandle $vmHandle -WriteMethod WriteInterfaceHvmmDrvInternal | Out-Null


try {

# ==============================================================================
# RESTORE MODE: Revert patch from backup file
# ==============================================================================

if ($Restore) {
    Write-Host "`n=== Restore Mode ===" -ForegroundColor $COLOR_INFO
    Write-Host ("  Backup file: {0}" -f $BackupPath) -ForegroundColor $COLOR_INFO

    $backup = Read-PatchBackup -Path $BackupPath
    if ($null -eq $backup) { return }

    Write-Host ("  Created:     {0}" -f $backup.Timestamp)        -ForegroundColor $COLOR_DEBUG
    Write-Host ("  PatchRVA:    0x{0:X}" -f $backup.PatchRVA)     -ForegroundColor $COLOR_INFO
    Write-Host ("  PatchLength: {0}"     -f $backup.PatchLength)   -ForegroundColor $COLOR_INFO
    Write-Host ("  Original:    {0}" -f (($backup.OriginalBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' ')) -ForegroundColor $COLOR_INFO
    Write-Host ("  Patched:     {0}" -f (($backup.PatchedBytes  | ForEach-Object { "{0:X2}" -f $_ }) -join ' ')) -ForegroundColor $COLOR_DEBUG

    # Get current securekernel info
    Select-HvlibPartition -PartitionHandle $vmHandle | Out-Null
    $skBase = Get-HvlibSecureKernelBase -PartitionHandle $vmHandle
    $skSize = Get-HvlibSecureKernelSize -PartitionHandle $vmHandle
    $skCr3  = Get-HvlibData2 -PartitionHandle $vmHandle -InformationClass HvddGetCr3Securekernel

    Write-Host ""
    Write-Host ("  Current SK Base: 0x{0:X}" -f $skBase) -ForegroundColor $COLOR_INFO
    Write-Host ("  Backup  SK Base: 0x{0:X}" -f $backup.SecurekernelBase) -ForegroundColor $COLOR_INFO

    if ($skBase -eq 0 -or $skCr3 -eq 0) {
        Write-Error "Securekernel not available — VBS may be disabled or VM was rebooted"
        return
    }

    # Get partition ID for VTL protection modification
    $partitionId = Get-HvlibData2 -PartitionHandle $vmHandle -InformationClass $HvddPartitionId

    # Strategy 1: Try saved physical address first (works if VM wasn't rebooted)
    $patchPhys  = [uint64]0
    $restoreOk  = $false
    $savedPhys  = $backup.PatchPhysicalAddress

    if ($savedPhys -ne 0) {
        Write-Host ""
        Write-Host ("  Trying saved physical address 0x{0:X}..." -f $savedPhys) -ForegroundColor $COLOR_INFO

        $currentBytes = Get-HvlibVmPhysicalMemory -prtnHandle $vmHandle -start_position $savedPhys -size $backup.PatchLength
        if ($null -ne $currentBytes -and $currentBytes.Length -ge $backup.PatchLength) {
            $currentHex = ($currentBytes[0..($backup.PatchLength - 1)] | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
            $patchedHex = ($backup.PatchedBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
            Write-Host ("  Current bytes: {0}" -f $currentHex) -ForegroundColor $COLOR_DEBUG

            if ($currentHex -eq $patchedHex) {
                Write-Host "  Patched bytes confirmed at saved address" -ForegroundColor $COLOR_SUCCESS
                $patchPhys = $savedPhys
            } else {
                $origHex = ($backup.OriginalBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
                if ($currentHex -eq $origHex) {
                    Write-Host "  Original bytes already present — patch was not active" -ForegroundColor $COLOR_WARN
                    Write-Host "  Nothing to restore." -ForegroundColor $COLOR_SUCCESS
                    return
                }
                Write-Host "  Bytes don't match — VM may have been rebooted" -ForegroundColor $COLOR_WARN
            }
        }
    }

    # Strategy 2: Walk page table to find current physical address
    if ($patchPhys -eq 0) {
        Write-Host ""
        Write-Host "  Walking VTL1 page table to find patch location..." -ForegroundColor $COLOR_INFO

        $patchVA = $skBase + $backup.PatchRVA
        Write-Host ("  Patch VA: 0x{0:X}" -f $patchVA) -ForegroundColor $COLOR_DEBUG

        $patchPhys = Resolve-PageTableAddress `
            -Handle $vmHandle `
            -DirectoryTableBase $skCr3 `
            -VirtualAddress $patchVA `
            -Quiet

        if ($patchPhys -eq 0) {
            Write-Error ("Failed to translate VA 0x{0:X} — cannot restore" -f $patchVA)
            return
        }

        Write-Host ("  Resolved PA: 0x{0:X}" -f $patchPhys) -ForegroundColor $COLOR_SUCCESS

        # Verify current bytes
        $currentBytes = Get-HvlibVmPhysicalMemory -prtnHandle $vmHandle -start_position $patchPhys -size $backup.PatchLength
        if ($null -ne $currentBytes) {
            $currentHex = ($currentBytes[0..($backup.PatchLength - 1)] | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
            $patchedHex = ($backup.PatchedBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
            $origHex    = ($backup.OriginalBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
            Write-Host ("  Current bytes: {0}" -f $currentHex) -ForegroundColor $COLOR_DEBUG

            if ($currentHex -eq $origHex) {
                Write-Host "  Original bytes already present — patch is not active" -ForegroundColor $COLOR_WARN
                Write-Host "  Nothing to restore." -ForegroundColor $COLOR_SUCCESS
                return
            }

            if ($currentHex -ne $patchedHex) {
                Write-Warning "  Current bytes don't match expected patched bytes — unexpected state"
                Write-Host ("  Expected: {0}" -f $patchedHex) -ForegroundColor $COLOR_WARN
                Write-Host ("  Found:    {0}" -f $currentHex) -ForegroundColor $COLOR_WARN
                Write-Host "  Proceeding with restore anyway..." -ForegroundColor $COLOR_WARN
            } else {
                Write-Host "  Patched bytes confirmed" -ForegroundColor $COLOR_SUCCESS
            }
        }
    }

    # Write original bytes back
    Write-Host ""
    Write-Host ("  Restoring {0} original bytes at PA 0x{1:X}..." -f $backup.PatchLength, $patchPhys) -ForegroundColor $COLOR_INFO

    # Remove VTL protection
    Invoke-HvModifyVtlProtectionMask -PartitionId $partitionId -PhysicalAddress $patchPhys | Out-Null

    # Write original bytes
    Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $vmHandle -StartPosition $patchPhys -Data $backup.OriginalBytes | Out-Null

    # Verify
    $verifyBytes = Get-HvlibVmPhysicalMemory -prtnHandle $vmHandle -start_position $patchPhys -size ($backup.PatchLength + 5)
    if ($null -ne $verifyBytes) {
        $verifyHex = ($verifyBytes[0..($backup.PatchLength - 1)] | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
        $origHex   = ($backup.OriginalBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
        $restoreOk = ($verifyHex -eq $origHex)

        Format-HexDump -Bytes ($verifyBytes | Select-Object -First ($backup.PatchLength + 5)) -BaseAddress $patchPhys
    }

    Write-Host ""
    if ($restoreOk) {
        Write-Host "========================================" -ForegroundColor $COLOR_SUCCESS
        Write-Host "  Securekernel restored successfully!"    -ForegroundColor $COLOR_SUCCESS
        Write-Host "  IUM debug patch has been reverted."     -ForegroundColor $COLOR_SUCCESS
        Write-Host "========================================" -ForegroundColor $COLOR_SUCCESS
    } else {
        Write-Host "========================================" -ForegroundColor $COLOR_ERROR
        Write-Host "  Restore verification FAILED!"           -ForegroundColor $COLOR_ERROR
        Write-Host "  Check VM state and try again."          -ForegroundColor $COLOR_ERROR
        Write-Host "========================================" -ForegroundColor $COLOR_ERROR
    }

    return
}


# ==============================================================================
# PHASE 1: Read securekernel image and perform symbol-based analysis
# ==============================================================================

Write-Host "`n=== Phase 1: Symbol-based analysis ===" -ForegroundColor $COLOR_INFO

Select-HvlibPartition -PartitionHandle $vmHandle | Out-Null

# Query securekernel info from the Hvlib SDK
$skBase = Get-HvlibSecureKernelBase -PartitionHandle $vmHandle
$skSize = Get-HvlibSecureKernelSize -PartitionHandle $vmHandle
$skCr3  = Get-HvlibData2 -PartitionHandle $vmHandle -InformationClass HvddGetCr3Securekernel

if ($skBase -eq 0 -or $skSize -eq 0 -or $skCr3 -eq 0) {
    Write-Error "Securekernel not found. Is VBS (Virtualization-Based Security) enabled in the VM?"
    return
}

Write-Host ("  Base: 0x{0:X16}" -f $skBase) -ForegroundColor $COLOR_SUCCESS
Write-Host ("  Size: 0x{0:X}"   -f $skSize) -ForegroundColor $COLOR_SUCCESS
Write-Host ("  CR3:  0x{0:X}"   -f $skCr3)  -ForegroundColor $COLOR_SUCCESS

# Read the full securekernel PE image via VTL1 page table walk
$skImageBytes = Read-SecurekernelVirtualMemory `
    -Handle $vmHandle `
    -CR3 $skCr3 `
    -VirtualAddress $skBase `
    -Size ([int]$skSize)

if ($null -eq $skImageBytes) {
    Write-Error "Failed to read securekernel image via page table walk"
    return
}

# Sanity check: verify MZ header
if ($skImageBytes[0] -ne 0x4D -or $skImageBytes[1] -ne 0x5A) {
    Write-Error "Invalid MZ header — the read data is not a valid PE image"
    return
}

Write-Host ("  Read {0:N0} bytes, MZ header verified" -f $skImageBytes.Length) -ForegroundColor $COLOR_SUCCESS

# Initialize Capstone disassembler (from Hvlib module)
if (-not (Initialize-Capstone -DllPath $CapstoneDllPath)) { return }

# Run the symbol-based patch finder (uses direct symbol lookup, no pre-loading needed)
Write-Host "`n--- Resolving symbols and analyzing code ---" -ForegroundColor $COLOR_INFO

$patchCtx = Find-PatchContext `
    -PartitionHandle $vmHandle `
    -ImageBytes $skImageBytes `
    -SecurekernelBase $skBase

if ($null -eq $patchCtx -or $patchCtx.PatchLen -eq 0) {
    Write-Error "Failed to find patch target in IumInvokeSecureService"
    return
}

# Display analysis results
Write-Host ""
Write-Host ("  Patch RVA:    0x{0:X}" -f $patchCtx.PatchOffset) -ForegroundColor $COLOR_SUCCESS
Write-Host ("  Patch length: 0x{0:X}" -f $patchCtx.PatchLen)    -ForegroundColor $COLOR_SUCCESS
Write-Host ("  RET RVA:      0x{0:X}" -f $patchCtx.RetOffset)   -ForegroundColor $COLOR_SUCCESS

# Show which functions contain the patch/RET addresses (symbol verification)
Show-PatchAddressContext `
    -PartitionHandle $vmHandle `
    -PatchRVA $patchCtx.PatchOffset `
    -RetRVA $patchCtx.RetOffset `
    -SecurekernelBase $skBase

if ($patchCtx.RetOffset -eq 0 -or $patchCtx.CheckPage.Length -eq 0) {
    Write-Error "Analysis incomplete: no RET instruction found for trap placement"
    return
}


# ==============================================================================
# PHASE 2: Patch the running VM
# ==============================================================================

# If the patch is already applied, nothing to do
if ($patchCtx.AlreadyPatched) {
    Write-Host ""
    Write-Host "=== Patch already applied! ===" -ForegroundColor $COLOR_WARN
    Write-Host "IUM process debugging is already enabled." -ForegroundColor $COLOR_SUCCESS
    return
}

Write-Host "`n=== Phase 2: VM Patching ===" -ForegroundColor $COLOR_INFO

# Get partition metadata
$partitionId = Get-HvlibData2 -PartitionHandle $vmHandle -InformationClass $HvddPartitionId
$numCpuRef   = $null
Get-HvlibData -PartitionHandle $vmHandle -InformationClass $HvddNumberOfCPU -Information ([ref]$numCpuRef) | Out-Null
$numCpu = [int]([uint64]$numCpuRef)

Write-Host ("  Partition ID: 0x{0:X}" -f $partitionId) -ForegroundColor $COLOR_INFO
Write-Host ("  CPU count:    {0}"     -f $numCpu)       -ForegroundColor $COLOR_INFO

# Prepare the NOP patch (same length as the error-code block)
$nopPatch = [byte[]]::new($patchCtx.PatchLen)
for ($i = 0; $i -lt $patchCtx.PatchLen; $i++) { $nopPatch[$i] = 0x90 }

# Calculate page-relative offsets for the RET instruction
$retOffsetInPage = [int]($patchCtx.RetOffset -band 0xFFF)
$retPageBase     = $patchCtx.RetOffset -band 0xFFFFFFFFFFFFF000

# Build a trimmed byte signature from the check page for physical memory scanning.
# We skip the first N bytes to avoid matching unrelated pages, focusing on the
# unique code region near the RET instruction.
$sigTrimOffset = $retOffsetInPage -band 0xF00
if     ($sigTrimOffset -gt 0x400) { $sigTrimOffset -= 0x200 }
elseif ($sigTrimOffset -gt 0x300) { $sigTrimOffset -= 0x100 }
else                              { $sigTrimOffset  = 0     }

$sigBytes = $patchCtx.CheckPage[$sigTrimOffset..($patchCtx.CheckPage.Length - 1)]


# ---- Step 2a: Scan physical memory for the page signature ----

Write-Host ""
Write-Host "Scanning physical memory for page signature..." -ForegroundColor $COLOR_INFO

$readAddr  = $ScanStartAddress
$foundAddr = [uint64]0

while ($true) {
    $data = Get-HvlibVmPhysicalMemory `
        -prtnHandle $vmHandle `
        -start_position ($readAddr + [uint64]$sigTrimOffset) `
        -size $sigBytes.Length

    if ($null -ne $data -and $data.Length -ge $sigBytes.Length) {
        if (Compare-ByteArrays -Source $data -Pattern $sigBytes) {
            Write-Host ("  MATCH found at physical address 0x{0:X16}" -f $readAddr) -ForegroundColor $COLOR_SUCCESS
            $foundAddr = $readAddr
            break
        }
    }

    $readAddr += $PAGE_SIZE

    # Progress indicator every 16 MB
    if (($readAddr -band 0xFFFFFF) -eq 0) {
        Write-Host ("  Scanning 0x{0:X16}..." -f $readAddr) -ForegroundColor $COLOR_DEBUG
    }

    # Safety limit: don't scan more than 4 GB
    if ($readAddr -gt ($ScanStartAddress + 0x100000000)) {
        Write-Error "Page signature not found within 4 GB scan range"
        return
    }
}


# ---- Step 2b: Write PAUSE+LOOP trap at the RET location ----
# The trap (F3 90 EB FC C3) creates an infinite loop at the RET instruction.
# When a VTL1 CPU executes this code path, it will spin here, allowing us
# to read its RIP/CR3 registers and determine the real securekernel base.

$trapAddr = $foundAddr + [uint64]$retOffsetInPage

if ($DryRun) {
    Write-Host ""
    Write-Host ("[DRY RUN] Would write trap at physical 0x{0:X16}" -f $trapAddr) -ForegroundColor $COLOR_WARN
    Write-Host "[DRY RUN] Skipping VM modification." -ForegroundColor $COLOR_WARN
    return
}

Write-Host ""
Write-Host ("Writing PAUSE+LOOP trap at physical 0x{0:X16}..." -f $trapAddr) -ForegroundColor $COLOR_INFO

# Remove VTL write protection on the target page
Invoke-HvModifyVtlProtectionMask -PartitionId $partitionId -PhysicalAddress $trapAddr | Out-Null

# Write the trap code
Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $vmHandle -StartPosition $trapAddr -Data $PATCH_CODE | Out-Null

# Verify the write persisted (VTL protection might have blocked it)
$verify = Get-HvlibVmPhysicalMemory -prtnHandle $vmHandle -start_position $trapAddr -size $PATCH_CODE.Length
$writeOk = $true
for ($i = 0; $i -lt $PATCH_CODE.Length; $i++) {
    if ($verify[$i] -ne $PATCH_CODE[$i]) { $writeOk = $false; break }
}

if ($writeOk) {
    Write-Host "  Trap write verified successfully" -ForegroundColor $COLOR_SUCCESS
}
else {
    Write-Host "  WARNING: Trap write did NOT persist! VTL protection may still be active." -ForegroundColor $COLOR_ERROR
}


# ---- Step 2c: Poll VTL1 VP registers until a CPU hits the trap ----

Write-Host ""
Write-Host "Waiting for a VTL1 virtual processor to hit the trap..." -ForegroundColor $COLOR_INFO

$finalSK  = [uint64]0
$guestCr3 = [uint64]0
$trapped  = $false

for ($attempt = 0; $attempt -lt 500; $attempt++) {
    for ($vp = 0; $vp -lt $numCpu; $vp++) {
        $cr3Reg = Get-HvlibVpRegister -PartitionHandle $vmHandle -VpIndex $vp -RegisterCode $HvX64RegisterCr3 -Vtl $Vtl1
        $ripReg = Get-HvlibVpRegister -PartitionHandle $vmHandle -VpIndex $vp -RegisterCode $HvX64RegisterRip -Vtl $Vtl1

        if ($null -eq $cr3Reg -or $null -eq $ripReg) { continue }

        # Check if RIP is near our trap location (within +/- 0x20 bytes)
        $ripLow = [int]($ripReg.Reg64 -band 0xFFF)
        if ($ripLow -gt ($retOffsetInPage - 0x20) -and $ripLow -lt ($retOffsetInPage + 0x20)) {
            $guestCr3 = $cr3Reg.Reg64
            $finalSK  = ($ripReg.Reg64 -band 0xFFFFFFFFFFFFF000) - $retPageBase

            Write-Host ("  VP{0} trapped! RIP=0x{1:X16}, CR3=0x{2:X16}" -f $vp, $ripReg.Reg64, $guestCr3) -ForegroundColor $COLOR_SUCCESS
            Write-Host ("  Securekernel base => 0x{0:X16}" -f $finalSK) -ForegroundColor $COLOR_SUCCESS
            $trapped = $true
            break
        }
    }

    if ($trapped) { break }
    Start-Sleep -Milliseconds 10
}

# If no VP hit the trap within ~5 seconds, revert and bail
if (-not $trapped) {
    Write-Host "  Timeout waiting for trap hit. Reverting..." -ForegroundColor $COLOR_ERROR
    Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $vmHandle -StartPosition $trapAddr -Data $REVERT_CODE | Out-Null
    return
}


# ---- Step 2d: Revert the trap and apply the actual NOP patch ----

Write-Host ""

# First, restore the RET instruction so the trapped VP can continue
Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $vmHandle -StartPosition $trapAddr -Data $REVERT_CODE | Out-Null
Write-Host "  Trap reverted (RET restored)" -ForegroundColor $COLOR_INFO

# Now translate the patch target VA → PA using the trapped VP's CR3
$patchVA   = $finalSK + $patchCtx.PatchOffset
$patchPhys = Resolve-PageTableAddress `
    -Handle $vmHandle `
    -DirectoryTableBase $guestCr3 `
    -VirtualAddress $patchVA `
    -Quiet

if ($patchPhys -ne 0) {
    # Read original bytes BEFORE patching (for backup)
    $origBytes = Get-HvlibVmPhysicalMemory -prtnHandle $vmHandle -start_position $patchPhys -size $patchCtx.PatchLen
    if ($null -eq $origBytes) {
        Write-Error ("Failed to read original bytes at PA 0x{0:X}" -f $patchPhys)
        return
    }
    $origBytes = [byte[]]$origBytes[0..($patchCtx.PatchLen - 1)]

    # Remove VTL protection on the patch page
    Invoke-HvModifyVtlProtectionMask -PartitionId $partitionId -PhysicalAddress $patchPhys | Out-Null

    # Overwrite the error-code block with NOPs
    $writeResult = Set-HvlibVmPhysicalMemoryBytes `
        -PartitionHandle $vmHandle `
        -StartPosition $patchPhys `
        -Data $nopPatch

    $resultColor = if ($writeResult) { $COLOR_SUCCESS } else { $COLOR_ERROR }
    Write-Host ("  NOP patch ({0} bytes) at phys 0x{1:X16}: {2}" -f $nopPatch.Length, $patchPhys, $writeResult) -ForegroundColor $resultColor

    # Show the patched bytes
    $verifyBytes = Get-HvlibVmPhysicalMemory -prtnHandle $vmHandle -start_position $patchPhys -size 0x10
    if ($verifyBytes) {
        Format-HexDump -Bytes ($verifyBytes | Select-Object -First 0x10) -BaseAddress $patchPhys
    }

    # Save backup for future restore
    Save-PatchBackup `
        -Path $BackupPath `
        -SecurekernelBase $finalSK `
        -PatchRVA $patchCtx.PatchOffset `
        -PatchLength $patchCtx.PatchLen `
        -OriginalBytes $origBytes `
        -PatchedBytes $nopPatch `
        -PatchPhysicalAddress $patchPhys `
        -RetRVA $patchCtx.RetOffset
}
else {
    Write-Error ("Failed to translate patch VA 0x{0:X16} to physical address" -f $patchVA)
}


# ---- Done! ----

Write-Host ""
Write-Host "========================================" -ForegroundColor $COLOR_SUCCESS
Write-Host "  IUM Debug patch applied successfully!" -ForegroundColor $COLOR_SUCCESS
Write-Host ""
Write-Host ("  Securekernel base: 0x{0:X}" -f $finalSK) -ForegroundColor $COLOR_SUCCESS
Write-Host ""
Write-Host "  To restore original bytes:" -ForegroundColor $COLOR_INFO
Write-Host ("  .\Invoke-SecurekernelIUMDebug-Lite.ps1 -Restore") -ForegroundColor $COLOR_INFO
Write-Host ""
Write-Host "  WinDbg command to load symbols:" -ForegroundColor $COLOR_INFO
Write-Host ("  .reload /f securekernel.exe=0x{0:X}" -f $finalSK) -ForegroundColor $COLOR_INFO
Write-Host "========================================" -ForegroundColor $COLOR_SUCCESS


} # end try
finally {
    # Always release the partition handle
    Close-HvlibPartition -handle $vmHandle | Out-Null
}

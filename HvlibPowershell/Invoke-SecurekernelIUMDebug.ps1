<#
.SYNOPSIS
    Secure Kernel IUM Debugging Tool - powershell version.
    
    Based on cbwang505's hvsecurekernel C# tool (https://github.com/cbwang505/SecurekernelIUMDebug), rewritten in PowerShell
    using Hvlib SDK primitives instead of raw DeviceIoControl/P/Invoke.

.DESCRIPTION
    Stripped-down version of Invoke-SecurekernelIUMDebug.ps1 that does ONLY
    the patch operation, in two phases:

      Phase 1 (analysis):
        1. Read securekernel.exe from VTL1 (SDK ReadVirtualMemory, page-walk fallback)
        2. Resolve IumInvokeSecureService / SkpsIsProcessDebuggingEnabled symbols
        3. Disassemble with Capstone, find the LEA -> JMP -> STATUS_ACCESS_DENIED
           error block (the bytes to NOP out)
        4. Pick the nearest RET as the trap anchor + page-signature source

      Phase 2 (patch):
        1. Scan VM physical memory for the trimmed CheckPage signature
        2. Write a PAUSE+LOOP trap at the RET location and poll VTL1 RIP until
           one CPU is spinning on it -> gives us the real securekernel base + CR3
        3. Revert the trap; translate the patch VA via that CR3; NOP-patch
           the error block

    Removed compared to -Lite (use the full -Lite script for these):
      - -Restore mode + backup save/load (Save-PatchBackup, Read-PatchBackup)
      - -DryRun mode
      - Symbol-context diagnostic (Show-PatchAddressContext / Resolve-AddressToSymbol)
      - Verification hex dumps after writes
      - "Already patched" short-circuit (still detected, just less verbose)

.PARAMETER DllPath
    Path to hvlibdotnet.dll. If omitted, read from .\Hvlib-Config.json or
    C:\hvlib\Hvlib-Config.json. No hardcoded fallback.

.PARAMETER VmName
    Target VM name. Same resolution as DllPath.

.PARAMETER CapstoneDllPath
    Path to capstone.dll. Auto-detected from Python packages if omitted.

.PARAMETER ScanStartAddress
    Starting physical address for the page scan. Default: 0x600000.
#>

param(
    [string]$DllPath,
    [string]$VmName,
    [string]$CapstoneDllPath,
    [uint64]$ScanStartAddress = 0x600000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


#region Hvlib_aux import (Capstone disassembly)
### ==============================================================================

###
### Hvlib_aux is loaded into the session via Hvlib's ScriptsToProcess, but we
### guard explicitly: a partial earlier import (Initialize-Capstone present but
### Invoke-CapstoneDisasm missing) would only fail mid-Phase1. Check all
### Capstone cmdlets we depend on; force-import if any is missing.
###

$requiredCapstoneCmds = @(
    'Initialize-Capstone',
    'Invoke-CapstoneDisasm',
    'Get-CapstoneBranchTarget',
    'Get-CapstoneLeaRipTarget'
)
$missing = @($requiredCapstoneCmds | Where-Object { -not (Get-Command $_ -EA SilentlyContinue) })
if ($missing.Count -gt 0) {
    $hvm = Get-Module Hvlib -ListAvailable | Select-Object -First 1
    $aux = if ($hvm) { Join-Path (Split-Path $hvm.Path) 'Hvlib_aux.psd1' } else { $null }
    if ($aux -and (Test-Path $aux)) { Import-Module $aux -Force -ErrorAction Stop }
    else                            { Import-Module Hvlib_aux -Force -ErrorAction Stop }
    $still = @($requiredCapstoneCmds | Where-Object { -not (Get-Command $_ -EA SilentlyContinue) })
    if ($still.Count -gt 0) { throw "Hvlib_aux loaded but missing: $($still -join ', ')" }
}

#endregion


#region Constants
### ==============================================================================

###
### Trap code: PAUSE + JMP $-2 + RET = an infinite spin loop. We write it at the
### RET location; any VTL1 CPU executing this path will get stuck spinning here,
### which lets us read its RIP/CR3 via Get-HvlibVpRegister.
###

$PATCH_CODE  = [byte[]]@(0xF3, 0x90, 0xEB, 0xFC, 0xC3)

###
### Five RET bytes - safe landing pad that effectively no-ops the trap when we
### need to revert it (the trapped VP will return; subsequent passes also return).
###

$REVERT_CODE = [byte[]]@(0xC3, 0xC3, 0xC3, 0xC3, 0xC3)

$PAGE_SIZE = 0x1000

###
### Hyper-V register codes (TLFS HV_REGISTER_NAME values)
###

$HvX64RegisterRip = 0x00020010
$HvX64RegisterCr3 = 0x00040002

###
### Console colour palette
###

$COLOR_INFO    = 'Cyan'
$COLOR_SUCCESS = 'Green'
$COLOR_WARN    = 'Yellow'
$COLOR_ERROR   = 'Red'
$COLOR_DEBUG   = 'DarkGray'

###
### x86-64 page-table PFN mask: bits 12..51. Bits 52..55 are AVL/software and
### Hyper-V uses them for VTL metadata - masking them in corrupts the PA.
###

$X64_PFN_MASK_4K = 0xFFFFFFFFFF000
$X64_PFN_MASK_2M = 0xFFFFFFFE00000
$X64_PFN_MASK_1G = 0xFFFFFC0000000

###
### Patch-finder magic: STATUS_ACCESS_DENIED (0xC0000022) in little-endian
###

$STATUS_ACCESS_DENIED_LE = [byte[]]@(0x22, 0x00, 0x00, 0xC0)

###
### Known offsets used for enum-base rebase fallback
###

$IUM_INVOKE_SECURE_SERVICE_RVA = 0x13B20

#endregion


# region Low-level helpers (VTL protection, physical read, page walk)
### ==============================================================================

function Invoke-HvlibModifyVtlProtection {
    <#
    .SYNOPSIS
        Page-align an address and lift VTL1 write protection on its page.
    .DESCRIPTION
        Calls HvCallModifyVtlProtectionMask (0x000C) via the SDK wrapper.
        Required before writing into pages owned by securekernel.
    .OUTPUTS
        [bool] $true if the hypercall succeeded (or returned a benign non-zero).
    #>
    param([uint64]$PartitionId, [uint64]$PhysicalAddress)

    $pageAligned = $PhysicalAddress -band 0xFFFFFFFFFFFFF000
    $result = [Hvlibdotnet.Hvlib]::ModifyVtlProtection($PartitionId, $pageAligned)

    if ($result -eq 0) {
        Write-Host ("  VTL protection lifted for 0x{0:X16}" -f $pageAligned) -ForegroundColor $COLOR_SUCCESS
        return $true
    }
    Write-Host ("  VTL protection hypercall result: 0x{0:X}" -f $result) -ForegroundColor $COLOR_WARN
    return ($result -ne 0xFFFFFFFF -and $result -ne 0xFFFFFFFE)
}


function Read-PhysicalUInt64 {
    <#
    .SYNOPSIS
        Read 8 bytes from guest physical memory and return as UInt64. 0 on error.
    #>
    param([uint64]$Handle, [uint64]$Address)

    $data = Get-HvlibVmPhysicalMemory -prtnHandle $Handle -start_position $Address -size 8
    if ($null -eq $data -or $data.Length -lt 8) { return [uint64]0 }
    return [BitConverter]::ToUInt64($data, 0)
}


function Resolve-PageTableAddress {
    <#
    .SYNOPSIS
        Translate a guest VA -> GPA by walking the 4-level x86-64 page table.
    .DESCRIPTION
        PML4 -> PDPT -> PD -> PT, with early-exit for 1 GB and 2 MB large pages
        (PS bit set). Returns 0 on any level failure.

        Uses the PFN mask from $X64_PFN_MASK_4K/_2M/_1G - critically NOT
        a 13-F mask, which would let Hyper-V's VTL-metadata bits 52..55 leak
        into the next-level physical address.
    #>
    param([uint64]$Handle, [uint64]$DirectoryTableBase, [uint64]$VirtualAddress)

    ###
    ### Decompose VA into the four 9-bit table indexes (PML4, PDPT, PD, PT)
    ###

    $pml4Idx = ($VirtualAddress -shr 39) -band 0x1FF
    $pdptIdx = ($VirtualAddress -shr 30) -band 0x1FF
    $pdIdx   = ($VirtualAddress -shr 21) -band 0x1FF
    $ptIdx   = ($VirtualAddress -shr 12) -band 0x1FF

    ###
    ### Level 4: PML4 entry
    ###

    $pml4e = Read-PhysicalUInt64 -Handle $Handle -Address ($DirectoryTableBase + [uint64]($pml4Idx * 8))
    if ($pml4e -eq 0) { return [uint64]0 }

    ###
    ### Level 3: PDPT entry; PS=1 means a 1 GB page maps directly here
    ###

    $pdpte = Read-PhysicalUInt64 -Handle $Handle -Address (($pml4e -band $X64_PFN_MASK_4K) + [uint64]($pdptIdx * 8))
    if ($pdpte -eq 0) { return [uint64]0 }
    if (($pdpte -band (1 -shl 7)) -ne 0) {
        return ($pdpte -band $X64_PFN_MASK_1G) + ($VirtualAddress -band 0x3FFFFFFF)
    }

    ###
    ### Level 2: PD entry; PS=1 means a 2 MB page maps directly here
    ###

    $pde = Read-PhysicalUInt64 -Handle $Handle -Address (($pdpte -band $X64_PFN_MASK_4K) + [uint64]($pdIdx * 8))
    if ($pde -eq 0) { return [uint64]0 }
    if (($pde -band (1 -shl 7)) -ne 0) {
        return ($pde -band $X64_PFN_MASK_2M) + ($VirtualAddress -band 0x1FFFFF)
    }

    ###
    ### Level 1: PT entry - the standard 4 KB-page case
    ###

    $pte = Read-PhysicalUInt64 -Handle $Handle -Address (($pde -band $X64_PFN_MASK_4K) + [uint64]($ptIdx * 8))
    if ($pte -eq 0) { return [uint64]0 }
    return ($pte -band $X64_PFN_MASK_4K) + ($VirtualAddress -band 0xFFF)
}


function Read-SecurekernelVirtualMemory {
    <#
    .SYNOPSIS
        Read a securekernel VA range. SDK first, page-walk fallback if SDK refuses.
    .DESCRIPTION
        Primary: Get-HvlibVmVirtualMemory (the SDK's ReadVirtualMemory).
        Fallback (only if SDK returns null / short): manual VTL1 page-walk
        page-by-page using the supplied CR3.
    .OUTPUTS
        [byte[]] of length Size, or $null on failure.
    #>
    param([uint64]$Handle, [uint64]$CR3, [uint64]$VirtualAddress, [int]$Size)

    ###
    ### Primary path
    ###

    try 
    {
        $sdkData = Get-HvlibVmVirtualMemory -prtnHandle $Handle -start_position $VirtualAddress `
                       -size ([uint64]$Size) -ErrorAction Stop 2>$null
    } catch { $sdkData = $null }
    if ($null -ne $sdkData -and $sdkData.Length -eq $Size) { return $sdkData }

    ###
    ### Fallback: page-by-page walk
    ###

    $result    = [byte[]]::new($Size)
    $offset    = 0
    $remaining = $Size
    while ($remaining -gt 0) {
        $currentVA  = $VirtualAddress + [uint64]$offset
        $pageOffset = [int]($currentVA -band 0xFFF)
        $chunkSize  = [Math]::Min($remaining, $PAGE_SIZE - $pageOffset)

        $physAddr = Resolve-PageTableAddress -Handle $Handle -DirectoryTableBase $CR3 -VirtualAddress $currentVA
        if ($physAddr -eq 0) { return $null }

        $data = Get-HvlibVmPhysicalMemory -prtnHandle $Handle -start_position $physAddr -size $chunkSize
        if ($null -eq $data) { return $null }

        [Array]::Copy($data, 0, $result, $offset, $chunkSize)
        $offset    += $chunkSize
        $remaining -= $chunkSize
    }

    return $result
}

#endregion


#region Analysis - parse hex / resolve symbols / find patch target
### ==============================================================================

function ConvertFrom-HexString {
    ###
    ### Parse a hex string like "0x1234ABCD" to UInt64.
    ###
    param([string]$HexText)
    return [uint64]::Parse($HexText.Replace("0x",""), [System.Globalization.NumberStyles]::HexNumber)
}


function Get-SecurekernelSymbol {
    <#
    .SYNOPSIS
        Resolve one symbol address inside securekernel via direct lookup.
    .OUTPUTS
        [uint64] VA of the symbol, or 0 if not found.
    #>
    param([uint64]$PartitionHandle, [string]$SymbolName)

    $va = Get-HvlibSymbolAddressDirect -PartitionHandle $PartitionHandle `
              -SymbolFullName "securekernel!$SymbolName" -EA SilentlyContinue 3>$null
    if ($null -eq $va) { return [uint64]0 }
    return [uint64]$va
}


function Get-IumServiceSymbols {
    <#
    .SYNOPSIS
        Resolve IumInvokeSecureService and SkpsIsProcessDebuggingEnabled VAs.
    .DESCRIPTION
        Fast path: SDK direct symbol lookup (Get-HvlibSymbolAddressDirect).
        Fallback: full enumeration via Get-HvlibAllSymbols + rebase to the
        runtime SecurekernelBase, since enum addresses sometimes use a stale
        cached base (detected via the known IumInvokeSecureService RVA 0x13B20).
    .OUTPUTS
        PSCustomObject { IumRVA, SkpsRVA } where each is a [uint32] (0 if missing),
        or $null if IumInvokeSecureService cannot be resolved at all.
    #>
    param([uint64]$PartitionHandle, [byte[]]$ImageBytes, [uint64]$SecurekernelBase)

    $iumVA  = Get-SecurekernelSymbol -PartitionHandle $PartitionHandle -SymbolName 'IumInvokeSecureService'
    $skpsVA = if ($iumVA -ne 0) {
        Get-SecurekernelSymbol -PartitionHandle $PartitionHandle -SymbolName 'SkpsIsProcessDebuggingEnabled'
    } else { [uint64]0 }

    ###
    ### Enumeration fallback
    ###

    if ($iumVA -eq 0 -or $skpsVA -eq 0) {
        Write-Host "  Direct lookup missed - trying full enumeration..." -ForegroundColor $COLOR_WARN
        $allSyms = Get-HvlibAllSymbols -PartitionHandle $PartitionHandle -DriverName "securekernel"
        if ($null -eq $allSyms -or $allSyms.Count -eq 0) {
            $allSyms = Get-HvlibAllSymbols -PartitionHandle $PartitionHandle -DriverName "securekernel.exe"
        }
        if ($null -ne $allSyms -and $allSyms.Count -gt 0) {
            ###
            ### Detect enum-base offset from the known IumInvokeSecureService RVA
            ###
            $iumRef = $allSyms | Where-Object { $_.Name -eq 'IumInvokeSecureService' } | Select-Object -First 1
            $enumBase = $SecurekernelBase
            if ($iumRef) {
                $iumEnumAddr = ConvertFrom-HexString $iumRef.Address
                $enumBase    = $iumEnumAddr - [uint64]$IUM_INVOKE_SECURE_SERVICE_RVA
            }
            if ($iumVA -eq 0 -and $iumRef) {
                $iumVA = $SecurekernelBase + ((ConvertFrom-HexString $iumRef.Address) - $enumBase)
            }
            if ($skpsVA -eq 0) {
                $skpsSym = $allSyms | Where-Object { $_.Name -eq 'SkpsIsProcessDebuggingEnabled' } | Select-Object -First 1
                if ($skpsSym) {
                    $skpsVA = $SecurekernelBase + ((ConvertFrom-HexString $skpsSym.Address) - $enumBase)
                }
            }
        }
    }

    if ($iumVA -eq 0) {
        Write-Error "Symbol IumInvokeSecureService not found by any method"
        return $null
    }

    ###
    ### Validate addresses are within the image (catches stale symbol cache)
    ###

    $imageSize = [uint64]$ImageBytes.Length
    if ($iumVA -lt $SecurekernelBase -or ($iumVA - $SecurekernelBase) -ge $imageSize) {
        Write-Error "IumInvokeSecureService VA 0x$($iumVA.ToString('X')) outside image - stale symbols, restart VM"
        return $null
    }
    $iumRVA  = [uint32]($iumVA - $SecurekernelBase)
    $skpsRVA = [uint32]0
    if ($skpsVA -ne 0 -and $skpsVA -ge $SecurekernelBase -and ($skpsVA - $SecurekernelBase) -lt $imageSize) {
        $skpsRVA = [uint32]($skpsVA - $SecurekernelBase)
    }

    Write-Host ("  IumInvokeSecureService RVA => 0x{0:X}" -f $iumRVA) -ForegroundColor $COLOR_SUCCESS
    if ($skpsRVA -ne 0) {
        Write-Host ("  SkpsIsProcessDebuggingEnabled RVA => 0x{0:X}" -f $skpsRVA) -ForegroundColor $COLOR_SUCCESS
    }
    [PSCustomObject]@{ IumRVA = $iumRVA; SkpsRVA = $skpsRVA }
}


function Find-AccessDeniedPatchTarget {
    <#
    .SYNOPSIS
        Walk disassembly of IumInvokeSecureService for the LEA -> JMP -> error
        block pattern. Returns the bytes-to-NOP location and the instruction
        index where we stopped (so caller can continue searching for RET).
    .OUTPUTS
        PSCustomObject {
            PatchOffset    [uint64]  RVA of the error block (bytes to NOP out)
            PatchLen       [int]     number of bytes to NOP
            AlreadyPatched [bool]    $true if a NOP sled is already there
            NextIdx        [int]     instruction index to resume RET search from
        }
        or $null if the pattern was not found.
    #>
    param(
        [object[]]$Instructions,
        [byte[]]$DumpBytes,
        [uint32]$IumRVA,
        [uint32]$SkpsRVA
    )

    $jdx = 0
    for ($idx = 0; $idx -lt $Instructions.Count; $idx++) {
        $insn = $Instructions[$idx]

        ###
        ### We're looking for: lea reg, [rip + offset_to_SkpsIsProcessDebuggingEnabled]
        ###

        if ($insn.Mnemonic -ne 'lea') { continue }
        $leaTarget = Get-CapstoneLeaRipTarget -Insn $insn
        if ($leaTarget -eq 0) { continue }

        ###
        ### If SkpsRVA is known, require exact match. Else accept any LEA [rip+X]
        ### and rely on the error-block pattern below to disambiguate.
        ###

        if ($SkpsRVA -ne 0 -and $leaTarget -ne $SkpsRVA) { continue }

        ###
        ### Walk forward up to 40 instructions looking for the JMP into the error block
        ###

        for ($jdx = $idx + 1; $jdx -lt [Math]::Min($idx + 40, $Instructions.Count); $jdx++) {
            $jInsn = $Instructions[$jdx]
            if ($jInsn.Mnemonic -ne 'jmp') { continue }

            $jTarget     = Get-CapstoneBranchTarget -Insn $jInsn
            $fetchOffset = [int]($jTarget - [uint64]$IumRVA)
            if ($fetchOffset -le 0 -or $fetchOffset -ge $DumpBytes.Length) { continue }

            ###
            ### Check 1: NOP sled => patch already applied
            ###

            $nopSled = Test-NopSled -DumpBytes $DumpBytes -At $fetchOffset
            if ($nopSled.IsSled) {
                return [PSCustomObject]@{
                    PatchOffset    = [uint64]$IumRVA + $fetchOffset
                    PatchLen       = $nopSled.Length
                    AlreadyPatched = $true
                    NextIdx        = $jdx
                }
            }

            ###
            ### Check 2: STATUS_ACCESS_DENIED + short JMP => the patch target
            ###
            
            $errorBlock = Find-AccessDeniedBlock -DumpBytes $DumpBytes -At $fetchOffset
            if ($errorBlock.Found) {
                return [PSCustomObject]@{
                    PatchOffset    = [uint64]$IumRVA + $fetchOffset
                    PatchLen       = $errorBlock.Length
                    AlreadyPatched = $false
                    NextIdx        = $jdx
                }
            }
        }
    }
    return $null
}


function Test-NopSled {
    ###
    ### Look for a >= 2 byte NOP sled at $DumpBytes[$At]. Returns {IsSled, Length}.
    ###
    param([byte[]]$DumpBytes, [int]$At)

    if ($DumpBytes[$At] -ne 0x90) { return [PSCustomObject]@{ IsSled = $false; Length = 0 } }
    $count = 0
    for ($n = $At; $n -lt $DumpBytes.Length -and $DumpBytes[$n] -eq 0x90; $n++) { $count++ }
    return [PSCustomObject]@{ IsSled = ($count -ge 2); Length = $count }
}


function Find-AccessDeniedBlock {
    <#
    .SYNOPSIS
        Look for the STATUS_ACCESS_DENIED (0xC0000022) constant followed by a
        short JMP (0xEB xx) within the next 0x20 bytes of $DumpBytes starting
        at $At. This is the error block we want to NOP out.
    .OUTPUTS
        PSCustomObject { Found = $true/$false; Length = bytes to NOP (includes JMP+disp) }
    #>
    param([byte[]]$DumpBytes, [int]$At)

    $sawConstant = $false
    for ($i = 0; $i -lt 0x20; $i++) {
        $idx = $At + $i

        ###
        ### Match STATUS_ACCESS_DENIED first
        ###
        if (-not $sawConstant -and ($idx + 4) -le $DumpBytes.Length -and
            [Hvlibdotnet.Hvlib]::BytesEqual($DumpBytes, $STATUS_ACCESS_DENIED_LE, $idx, 0, 4))
        {
            $sawConstant = $true
        }
        ###
        ### After the constant, find the closing short JMP -> we've covered the block
        ###
        if ($sawConstant -and $idx -lt $DumpBytes.Length -and $DumpBytes[$idx] -eq 0xEB) {
            return [PSCustomObject]@{ Found = $true; Length = $i + 2 }
        }
    }
    return [PSCustomObject]@{ Found = $false; Length = 0 }
}


function Find-NearestRet {
    <#
    .SYNOPSIS
        Starting at $StartIdx, find the first RET in $Instructions. Return its
        RVA and the page-prefix byte signature ending just before it (used for
        scanning physical memory to locate the running securekernel page).
    .OUTPUTS
        PSCustomObject { RetOffset = [uint64]; CheckPage = [byte[]] }
        (RetOffset = 0 / CheckPage = @() if no RET found.)
    #>
    param(
        [object[]]$Instructions,
        [int]$StartIdx,
        [byte[]]$DumpBytes,
        [uint32]$IumRVA
    )

    for ($ridx = $StartIdx; $ridx -lt $Instructions.Count; $ridx++) {
        $rInsn = $Instructions[$ridx]
        if ($rInsn.Mnemonic -ne 'ret') { continue }

        $retRVA         = [uint64]$IumRVA + $rInsn.Offset
        $retPageOffset  = [int]($retRVA -band 0xFFF)
        $pageStartInBuf = [int64]$rInsn.Offset - [int64]$retPageOffset
        if ($pageStartInBuf -lt 0) { $pageStartInBuf = 0 }

        return [PSCustomObject]@{
            RetOffset = $retRVA
            CheckPage = [byte[]]$DumpBytes[[int]$pageStartInBuf..([int]$rInsn.Offset - 1)]
        }
    }
    return [PSCustomObject]@{ RetOffset = [uint64]0; CheckPage = [byte[]]@() }
}


function Find-PatchContext {
    <#
    .SYNOPSIS
        Top-level analysis: resolve symbols, disassemble IumInvokeSecureService,
        find the patch target, find the nearest RET for the trap anchor.
    .OUTPUTS
        PSCustomObject {
            PatchOffset    [uint64]  RVA of bytes to NOP
            PatchLen       [int]     number of bytes
            RetOffset      [uint64]  RVA of RET (trap location)
            CheckPage      [byte[]]  page-prefix signature for memory scan
            AlreadyPatched [bool]
        }
        or $null on failure.
    #>
    param([uint64]$PartitionHandle, [byte[]]$ImageBytes, [uint64]$SecurekernelBase)

    $syms = Get-IumServiceSymbols -PartitionHandle $PartitionHandle `
                -ImageBytes $ImageBytes -SecurekernelBase $SecurekernelBase
    if ($null -eq $syms) { return $null }

    ###
    ### Slice up to 32 KB of the IumInvokeSecureService body for disassembly
    ###
    $readLen   = [Math]::Min(0x8000, $ImageBytes.Length - $syms.IumRVA)
    $dumpBytes = [byte[]]::new($readLen)
    [Array]::Copy($ImageBytes, $syms.IumRVA, $dumpBytes, 0, $readLen)
    $instructions = Invoke-CapstoneDisasm -Bytes $dumpBytes -BaseAddress ([uint64]$syms.IumRVA)

    $target = Find-AccessDeniedPatchTarget -Instructions $instructions -DumpBytes $dumpBytes `
                  -IumRVA $syms.IumRVA -SkpsRVA $syms.SkpsRVA
    if ($null -eq $target) {
        Write-Error "No LEA -> SkpsIsProcessDebuggingEnabled pattern found"
        return $null
    }

    $ret = Find-NearestRet -Instructions $instructions -StartIdx $target.NextIdx `
               -DumpBytes $dumpBytes -IumRVA $syms.IumRVA

    [PSCustomObject]@{
        PatchOffset    = $target.PatchOffset
        PatchLen       = $target.PatchLen
        RetOffset      = $ret.RetOffset
        CheckPage      = $ret.CheckPage
        AlreadyPatched = $target.AlreadyPatched
    }
}

#endregion


#region Session - configuration + VM connection
### ==============================================================================

function Resolve-ScriptConfig {
    <#
    .SYNOPSIS
        Resolve DllPath / VmName from parameters or one of the JSON config files.
    .DESCRIPTION
        Source priority:
          1. Explicit -DllPath / -VmName parameters
          2. .\Hvlib-Config.json   (script directory)
          3. C:\hvlib\Hvlib-Config.json
        Aborts with Write-Error if a value is still missing after all sources.
    .OUTPUTS
        PSCustomObject { DllPath, VmName, CfgUsed } or $null on error.
    #>
    param([string]$DllPath, [string]$VmName)

    $cfgUsed = $null
    if (-not $DllPath -or -not $VmName) {
        $candidates = @(
            (Join-Path $PSScriptRoot "Hvlib-Config.json"),
            "C:\hvlib\Hvlib-Config.json"
        )
        foreach ($cfgPath in $candidates) {
            if (-not (Test-Path $cfgPath)) { continue }
            try   { $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json }
            catch { Write-Error "Failed to parse '$cfgPath': $($_.Exception.Message)"; return $null }
            if (-not $DllPath -and $cfg.DllPath) { $DllPath = $cfg.DllPath }
            if (-not $VmName  -and $cfg.VmName)  { $VmName  = $cfg.VmName }
            $cfgUsed = $cfgPath
            break
        }
    }
    if (-not $DllPath)             { Write-Error "DllPath not configured (use -DllPath or Hvlib-Config.json)"; return $null }
    if (-not $VmName)              { Write-Error "VmName not configured (use -VmName or Hvlib-Config.json)";  return $null }
    if (-not (Test-Path $DllPath)) { Write-Error "DllPath '$DllPath' does not exist on disk";                  return $null }

    [PSCustomObject]@{ DllPath = $DllPath; VmName = $VmName; CfgUsed = $cfgUsed }
}


function Initialize-VmSession {
    <#
    .SYNOPSIS
        Load the SDK, resolve the partition, switch WriteMethod to
        WriteInterfaceHvmmDrvInternal (bypasses VTL protection).
    .OUTPUTS
        [uint64] partition handle, or 0 on failure.
    #>
    param([string]$DllPath, [string]$VmName)

    Get-Hvlib -path_to_dll $DllPath | Out-Null

    $vmHandle = Get-HvlibPartition -VmName $VmName
    if ($null -eq $vmHandle -or $vmHandle -eq 0) {
        Write-Error "VM '$VmName' not found"
        return [uint64]0
    }

    Set-HvlibWriteMethod -PartitionHandle $vmHandle -WriteMethod WriteInterfaceHvmmDrvInternal | Out-Null
    return [uint64]$vmHandle
}

#endregion


#region Phase 1 - read securekernel + locate the patch target
### ==============================================================================

function Invoke-Phase1Analysis {
    <#
    .SYNOPSIS
        Read securekernel from VTL1, initialise Capstone, run Find-PatchContext.
    .OUTPUTS
        $patchCtx (including AlreadyPatched flag) or $null on any failure.
    #>
    param([uint64]$VmHandle, [string]$CapstoneDllPath)

    Write-Host "`n=== Phase 1: Symbol-based analysis ===" -ForegroundColor $COLOR_INFO
    Select-HvlibPartition -PartitionHandle $VmHandle | Out-Null

    $skBase = Get-HvlibSecureKernelBase -PartitionHandle $VmHandle
    $skSize = Get-HvlibSecureKernelSize -PartitionHandle $VmHandle
    $skCr3  = Get-HvlibData2 -PartitionHandle $VmHandle -InformationClass HvddGetCr3Securekernel
    if ($skBase -eq 0 -or $skSize -eq 0 -or $skCr3 -eq 0) {
        Write-Error "Securekernel not found - is VBS enabled in the VM?"
        return $null
    }
    Write-Host ("  Base: 0x{0:X16}  Size: 0x{1:X}  CR3: 0x{2:X}" -f $skBase, $skSize, $skCr3) -ForegroundColor $COLOR_SUCCESS

    $skImageBytes = Read-SecurekernelVirtualMemory -Handle $VmHandle -CR3 $skCr3 `
                        -VirtualAddress $skBase -Size ([int]$skSize)
    if ($null -eq $skImageBytes) { Write-Error "Failed to read securekernel image"; return $null }
    if ($skImageBytes[0] -ne 0x4D -or $skImageBytes[1] -ne 0x5A) { Write-Error "Invalid MZ header"; return $null }
    Write-Host ("  Read {0:N0} bytes, MZ verified" -f $skImageBytes.Length) -ForegroundColor $COLOR_SUCCESS

    if (-not (Initialize-Capstone -DllPath $CapstoneDllPath)) { return $null }

    $patchCtx = Find-PatchContext -PartitionHandle $VmHandle `
                    -ImageBytes $skImageBytes -SecurekernelBase $skBase
    if ($null -eq $patchCtx -or $patchCtx.PatchLen -eq 0) { Write-Error "Failed to find patch target"; return $null }
    if ($patchCtx.RetOffset -eq 0 -or $patchCtx.CheckPage.Length -eq 0) {
        Write-Error "No RET found for trap placement"; return $null
    }

    Write-Host ("  Patch RVA: 0x{0:X}  len: 0x{1:X}  RET RVA: 0x{2:X}" -f `
        $patchCtx.PatchOffset, $patchCtx.PatchLen, $patchCtx.RetOffset) -ForegroundColor $COLOR_SUCCESS
    return $patchCtx
}

#endregion


#region Phase 2 - scan, trap, NOP-patch
### ==============================================================================

function New-NopBytes {
    ###
    ### Create a [byte[]] filled with 0x90 of the given length.
    ###
    param([int]$Length)
    $b = [byte[]]::new($Length)
    for ($i = 0; $i -lt $Length; $i++) { $b[$i] = 0x90 }
    return $b
}


function Get-TrimmedPageSignature {
    <#
    .SYNOPSIS
        Build a trimmed byte signature from $CheckPage suitable for scanning
        physical memory page-by-page.
    .DESCRIPTION
        The leading bytes of the page may match unrelated pages (common
        prologue patterns). We trim a fraction (0x100..0x200) based on where
        the RET sits in its page, keeping only the unique tail.
    .OUTPUTS
        PSCustomObject { SigBytes = [byte[]]; TrimOffset = [int] }
    #>
    param([byte[]]$CheckPage, [int]$RetOffsetInPage)

    $trimOffset = $RetOffsetInPage -band 0xF00
    if     ($trimOffset -gt 0x400) { $trimOffset -= 0x200 }
    elseif ($trimOffset -gt 0x300) { $trimOffset -= 0x100 }
    else                           { $trimOffset  = 0     }
    $sig = [byte[]]($CheckPage[$trimOffset..($CheckPage.Length - 1)])
    return [PSCustomObject]@{ SigBytes = $sig; TrimOffset = $trimOffset }
}


function Search-PageSignature {
    <#
    .SYNOPSIS
        Scan physical memory page-by-page for a byte signature.
    .OUTPUTS
        [uint64] page-aligned PA that matched, or 0 if not found in 4 GB.
    #>
    param(
        [uint64]$VmHandle,
        [byte[]]$SigBytes,
        [int]$SigTrimOffset,
        [uint64]$ScanStartAddress
    )

    Write-Host "Scanning physical memory for page signature..." -ForegroundColor $COLOR_INFO
    $readAddr = $ScanStartAddress
    $maxAddr  = $ScanStartAddress + 0x100000000  # cap at +4 GB

    while ($readAddr -le $maxAddr) {
        $data = Get-HvlibVmPhysicalMemory -prtnHandle $VmHandle `
                    -start_position ($readAddr + [uint64]$SigTrimOffset) -size $SigBytes.Length
        if ($null -ne $data -and $data.Length -ge $SigBytes.Length -and `
            [Hvlibdotnet.Hvlib]::BytesEqual($data, $SigBytes, 0, 0, $SigBytes.Length))
        {
            Write-Host ("  MATCH at physical 0x{0:X16}" -f $readAddr) -ForegroundColor $COLOR_SUCCESS
            return [uint64]$readAddr
        }
        $readAddr += $PAGE_SIZE
        if (($readAddr -band 0xFFFFFF) -eq 0) {
            Write-Host ("  Scanning 0x{0:X16}..." -f $readAddr) -ForegroundColor $COLOR_DEBUG
        }
    }
    Write-Error "Signature not found within 4 GB"
    return [uint64]0
}


function Wait-Vtl1TrapHit {
    <#
    .SYNOPSIS
        Poll VTL1 RIP/CR3 across all VPs until one is spinning near
        $RetOffsetInPage (within +/- 0x20 bytes of the trap).
    .OUTPUTS
        PSCustomObject {
            Trapped  [bool]
            FinalSK  [uint64]  resolved real securekernel base from the trapped RIP
            GuestCr3 [uint64]  CR3 of the trapped VP (used to translate patch VA)
        }
    #>
    param(
        [uint64]$VmHandle,
        [int]$NumCpu,
        [int]$RetOffsetInPage,
        [uint64]$RetPageBase,
        [int]$MaxAttempts = 500
    )

    Write-Host "Waiting for a VTL1 VP to hit the trap..." -ForegroundColor $COLOR_INFO
    $ripMin = $RetOffsetInPage - 0x20
    $ripMax = $RetOffsetInPage + 0x20

    for ($attempt = 0; $attempt -lt $MaxAttempts; $attempt++) {
        for ($vp = 0; $vp -lt $NumCpu; $vp++) 
        {
            $cr3Reg = Get-HvlibVpRegister -PartitionHandle $VmHandle -VpIndex $vp -RegisterCode $HvX64RegisterCr3 -Vtl ([Hvlibdotnet.Hvlib+VTL_LEVEL]::Vtl1)
            $ripReg = Get-HvlibVpRegister -PartitionHandle $VmHandle -VpIndex $vp -RegisterCode $HvX64RegisterRip -Vtl ([Hvlibdotnet.Hvlib+VTL_LEVEL]::Vtl1)

            if ($null -eq $cr3Reg -or $null -eq $ripReg) { continue }

            $ripLow = [int]($ripReg.Reg64 -band 0xFFF)

            if ($ripLow -gt $ripMin -and $ripLow -lt $ripMax) 
            {
                $finalSK = ($ripReg.Reg64 -band 0xFFFFFFFFFFFFF000) - $RetPageBase
                Write-Host ("  VP{0} trapped! RIP=0x{1:X16} CR3=0x{2:X16}" -f $vp, $ripReg.Reg64, $cr3Reg.Reg64) -ForegroundColor $COLOR_SUCCESS
                return [PSCustomObject]@{ Trapped = $true; FinalSK = [uint64]$finalSK; GuestCr3 = [uint64]$cr3Reg.Reg64 }
            }
        }

        Start-Sleep -Milliseconds 10
    }
    return [PSCustomObject]@{ Trapped = $false; FinalSK = [uint64]0; GuestCr3 = [uint64]0 }
}


function Get-VmCpuCount {
    ###
    ### Pull the CPU count via HvddNumberOfCPU information class.
    ###
    param([uint64]$VmHandle)
    $cpuRef = $null
    Get-HvlibData -PartitionHandle $VmHandle `
        -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddNumberOfCPU) `
        -Information ([ref]$cpuRef) | Out-Null
    return [int]([uint64]$cpuRef)
}


function Write-VtlPatchedBytes {
    ###
    ### Lift VTL protection on the page containing $PhysAddr, write $Bytes there.
    ### Returns the bool result of Set-HvlibVmPhysicalMemoryBytes.
    ###
    param([uint64]$VmHandle, [uint64]$PartitionId, [uint64]$PhysAddr, [byte[]]$Bytes)
    Invoke-HvlibModifyVtlProtection -PartitionId $PartitionId -PhysicalAddress $PhysAddr | Out-Null
    return Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $VmHandle -StartPosition $PhysAddr -Data $Bytes
}


function Invoke-Phase2Patch {
    <#
    .SYNOPSIS
        Scan physical memory for the patch page, write the PAUSE+LOOP trap,
        poll until a VTL1 VP is trapped, revert the trap, then NOP-patch the
        STATUS_ACCESS_DENIED error block.
    .OUTPUTS
        [bool] $true on successful NOP write.
    #>
    param([uint64]$VmHandle, [object]$PatchCtx, [uint64]$ScanStartAddress)

    Write-Host "`n=== Phase 2: VM Patching ===" -ForegroundColor $COLOR_INFO

    $partitionId = Get-HvlibData2 -PartitionHandle $VmHandle `
                       -InformationClass ([Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]::HvddPartitionId)
    $numCpu = Get-VmCpuCount -VmHandle $VmHandle

    $nopPatch        = New-NopBytes -Length $PatchCtx.PatchLen
    $retOffsetInPage = [int]($PatchCtx.RetOffset -band 0xFFF)
    $retPageBase     = $PatchCtx.RetOffset -band 0xFFFFFFFFFFFFF000
    $sig             = Get-TrimmedPageSignature -CheckPage $PatchCtx.CheckPage -RetOffsetInPage $retOffsetInPage

    ###
    ### Locate the running page in physical memory
    ###
    $foundAddr = Search-PageSignature -VmHandle $VmHandle `
                     -SigBytes $sig.SigBytes -SigTrimOffset $sig.TrimOffset `
                     -ScanStartAddress $ScanStartAddress
    if ($foundAddr -eq 0) { return $false }

    ###
    ### Plant the trap at the RET
    ###
    $trapAddr = $foundAddr + [uint64]$retOffsetInPage
    Write-Host ("Writing PAUSE+LOOP trap at 0x{0:X16}..." -f $trapAddr) -ForegroundColor $COLOR_INFO
    Write-VtlPatchedBytes -VmHandle $VmHandle -PartitionId $partitionId `
        -PhysAddr $trapAddr -Bytes $PATCH_CODE | Out-Null

    ###
    ### Wait for a VTL1 VP to hit it
    ###
    $hit = Wait-Vtl1TrapHit -VmHandle $VmHandle -NumCpu $numCpu `
               -RetOffsetInPage $retOffsetInPage -RetPageBase $retPageBase
    if (-not $hit.Trapped) {
        Write-Host "Timeout. Reverting trap..." -ForegroundColor $COLOR_ERROR
        Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $VmHandle -StartPosition $trapAddr -Data $REVERT_CODE | Out-Null
        return $false
    }

    ###
    ### Revert trap so the trapped VP continues, then NOP-patch the error block
    ###
    Set-HvlibVmPhysicalMemoryBytes -PartitionHandle $VmHandle -StartPosition $trapAddr -Data $REVERT_CODE | Out-Null
    Write-Host "  Trap reverted" -ForegroundColor $COLOR_INFO

    $patchVA   = $hit.FinalSK + $PatchCtx.PatchOffset
    $patchPhys = Resolve-PageTableAddress -Handle $VmHandle -DirectoryTableBase $hit.GuestCr3 -VirtualAddress $patchVA
    if ($patchPhys -eq 0) {
        Write-Error ("Failed to translate patch VA 0x{0:X16}" -f $patchVA); return $false
    }

    $writeResult = Write-VtlPatchedBytes -VmHandle $VmHandle -PartitionId $partitionId `
                       -PhysAddr $patchPhys -Bytes $nopPatch
    $resultColor = if ($writeResult) { $COLOR_SUCCESS } else { $COLOR_ERROR }
    Write-Host ("  NOP patch ({0} bytes) at 0x{1:X16}: {2}" -f $nopPatch.Length, $patchPhys, $writeResult) -ForegroundColor $resultColor

    Write-Host "`n=== IUM debug patch applied ===" -ForegroundColor $COLOR_SUCCESS
    Write-Host ("Securekernel base: 0x{0:X}" -f $hit.FinalSK) -ForegroundColor $COLOR_SUCCESS
    return [bool]$writeResult
}

#endregion


#region Main
### ==============================================================================

Write-Host "`n  Secure Kernel IUM Debug Tool`n" -ForegroundColor $COLOR_INFO

$cfg = Resolve-ScriptConfig -DllPath $DllPath -VmName $VmName
if ($null -eq $cfg) { return }

Write-Host "DLL:  $($cfg.DllPath)" -ForegroundColor $COLOR_INFO
Write-Host "VM:   $($cfg.VmName)"  -ForegroundColor $COLOR_INFO
if ($cfg.CfgUsed) { Write-Host "Cfg:  $($cfg.CfgUsed)" -ForegroundColor $COLOR_DEBUG }
Write-Host ""

$vmHandle = Initialize-VmSession -DllPath $cfg.DllPath -VmName $cfg.VmName
if ($vmHandle -eq 0) { return }

try {
    $patchCtx = Invoke-Phase1Analysis -VmHandle $vmHandle -CapstoneDllPath $CapstoneDllPath
    if ($null -eq $patchCtx) { return }

    if ($patchCtx.AlreadyPatched) {
        Write-Host "`n=== Patch already applied - nothing to do ===" -ForegroundColor $COLOR_WARN
        return
    }

    Invoke-Phase2Patch -VmHandle $vmHandle -PatchCtx $patchCtx -ScanStartAddress $ScanStartAddress | Out-Null
}
finally {
    Close-HvlibPartition -handle $vmHandle | Out-Null
    Close-Hvlib | Out-Null
}

#endregion

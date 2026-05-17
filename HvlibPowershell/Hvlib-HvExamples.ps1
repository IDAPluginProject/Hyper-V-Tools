# ==============================================================================
# Hvlib-HvExamples.ps1
# Version: 1.0.0
# Description: Concrete hypercall examples for every known Hyper-V hypercall.
#              Each function invokes a specific hypercall with TLFS-defined
#              input structs and checks HV_STATUS_SUCCESS (Ok=$true).
#
# HOW TO USE:
#   1. Dot-source:  . .\Hvlib-HvExamples.ps1
#   2. Individual:  Example-HvCallReadGpa -VmName "Windows Server 2025"
#   3. Run all:     Invoke-AllHvExamples -VmName "Windows Server 2025"
#
# PREREQUISITES:
#   - Hvlib module loaded (hvlibdotnet.dll)
#   - Hvlib.Hypercalls module (Invoke-HypercallRaw, $HvCallCode)
#   - Running VM with hvmm.sys driver
#
# NAMING:
#   Function names match hvgdk.h:  Example-HvCallReadGpa, Example-HvCallPerfNop, etc.
#   Struct layouts from hvgdk.h / TLFS are documented in .SYNOPSIS for each function.
#
# Change Log:
#   v1.0.0 - Complete table: all non-Reserved hypercalls (0x0001..0x00FD, 0x0101,
#            0x8001..0x8006) — typed wrappers where available, generic otherwise.
# ==============================================================================

#requires -Version 7.0


# ==============================================================================
#region Configuration & module loading
# ==============================================================================

$script:DEFAULT_DLL_PATH = "C:\Distr\LiveCloudKd_public\hvlibdotnet.dll"
$script:DEFAULT_VM_NAME  = "Windows Server 2025"

function Get-HvlibConfig {
    $config = @{ DllPath = $null; VmName = $null }
    $jsonPaths = @(
        (Join-Path $PSScriptRoot "Hvlib-Config.json"),
        "C:\Projects\hvlib_launcher\Hvlib-Config.json"
    )
    foreach ($p in $jsonPaths) {
        if (Test-Path $p) {
            $j = Get-Content $p -Raw | ConvertFrom-Json
            if ($j.DllPath) { $config.DllPath = $j.DllPath }
            if ($j.VmName)  { $config.VmName  = $j.VmName }
            break
        }
    }
    $regPath = "HKLM:\SOFTWARE\LiveCloudKd\params"
    if (Test-Path $regPath) {
        $reg = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        if (-not $config.DllPath -and $reg.DllPath) { $config.DllPath = $reg.DllPath }
        if (-not $config.VmName  -and $reg.VmName)  { $config.VmName  = $reg.VmName }
    }
    return $config
}

$script:_config = Get-HvlibConfig
$script:DllPath = if ($script:_config.DllPath) { $script:_config.DllPath } else { $script:DEFAULT_DLL_PATH }
$script:VmName  = if ($script:_config.VmName)  { $script:_config.VmName }  else { $script:DEFAULT_VM_NAME }

Import-Module Hvlib -Force -ErrorAction SilentlyContinue
Import-Module Hvlib.Hypercalls -Force -ErrorAction SilentlyContinue

if (-not (Get-Command Invoke-HypercallRaw -ErrorAction SilentlyContinue)) {
    Write-Warning "Hvlib.Hypercalls module not found."
    return
}

#endregion


# ==============================================================================
#region Shared helpers
# ==============================================================================

function Open-TestPartition {
    <# Opens partition, returns context hashtable with Handle, PartitionId, PhysAddr, SymVA. #>
    param([string]$VmName = $script:VmName)

    # Ensure DLL is loaded (idempotent — Get-Hvlib returns true if already loaded)
    if (-not $script:_hvlibInitialized) {
        $initResult = Get-Hvlib -path_to_dll $script:DllPath
        if ($initResult) { $script:_hvlibInitialized = $true }
    }

    $handle = Get-HvlibPartition -VmName $VmName
    if (-not $handle -or $handle -eq 0) { Write-Warning "VM '$VmName' not found"; return $null }

    $IC = [Hvlibdotnet.Hvlib+HVDD_INFORMATION_CLASS]
    $partitionId = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddPartitionId
    $kernelBase  = Get-HvlibData2 -PartitionHandle $handle -InformationClass $IC::HvddKernelBase

    $symVA   = Get-HvlibSymbolAddressDirect $handle "nt!KeBugCheckEx"
    $physAddr = [uint64]0
    if ($symVA -and $symVA -ne 0) {
        $physAddr = Get-HvlibPhysicalAddress -PartitionHandle $handle -VirtualAddress $symVA
    }

    @{
        Handle      = $handle
        PartitionId = [uint64]$partitionId
        KernelBase  = [uint64]$kernelBase
        SymVA       = [uint64]$symVA
        PhysAddr    = [uint64]$physAddr
    }
}

function Write-HvResult {
    <# Standard one-line result output. #>
    param([string]$Name, [uint32]$Code, [bool]$Ok, [string]$Extra = "")
    $status = if ($Ok) { "HV_STATUS_SUCCESS" } else { "FAILED" }
    $color  = if ($Ok) { "Green" } else { "Red" }
    $line   = "  [{0}] 0x{1:X4} {2,-45}" -f $status, $Code, $Name
    if ($Extra) { $line += "  $Extra" }
    Write-Host $line -ForegroundColor $color
}

#endregion


# ==============================================================================
#region Address space management (0x0001 – 0x0003)
# ==============================================================================

function Example-HvCallSwitchVirtualAddressSpace {
    <# .SYNOPSIS HvCallSwitchVirtualAddressSpace (0x0001) — switch to a new address space by ID. Input: { AddressSpace: UInt64 } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSwitchVirtualAddressSpace -InputData ([ordered]@{
        AddressSpace = [uint64]0
    })
    Write-HvResult "HvCallSwitchVirtualAddressSpace" 0x0001 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushVirtualAddressSpace {
    <# .SYNOPSIS HvCallFlushVirtualAddressSpace (0x0002). Input: { AddressSpace(8), Flags(8), ProcessorMask(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushVirtualAddressSpace -InputData ([ordered]@{
        AddressSpace  = [uint64]0
        Flags         = [uint64]0x0002   # HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES
        ProcessorMask = [uint64]::MaxValue
    })
    Write-HvResult "HvCallFlushVirtualAddressSpace" 0x0002 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushVirtualAddressList {
    <# .SYNOPSIS HvCallFlushVirtualAddressList (0x0003) — rep. Input: Header(24) + GvaList[]. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushVirtualAddressList -InputData ([ordered]@{
        AddressSpace  = [uint64]0
        Flags         = [uint64]0
        ProcessorMask = [uint64]::MaxValue
        GvaPage0      = [uint64]0
    }) -CountOfElements 1
    Write-HvResult "HvCallFlushVirtualAddressList" 0x0003 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Runtime / power (0x0004 – 0x0007)
# ==============================================================================

function Example-HvCallGetLogicalProcessorRunTime {
    <# .SYNOPSIS HvCallGetLogicalProcessorRunTime (0x0004). Output: { GlobalTime(8), LocalRunTime(8), GroupRunTime(8), HypervisorTime(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetLogicalProcessorRunTime -OutputSize 32
    $extra = ""
    if ($r.Ok -and $r.OutputBytes.Length -ge 32) {
        $global   = [BitConverter]::ToUInt64($r.OutputBytes, 0)
        $localRun = [BitConverter]::ToUInt64($r.OutputBytes, 8)
        $extra = "Global={0}, Local={1}" -f $global, $localRun
    }
    Write-HvResult "HvCallGetLogicalProcessorRunTime" 0x0004 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUpdateHvProcessorFeatures {
    <# .SYNOPSIS HvCallUpdateHvProcessorFeatures (0x0005). Input: { Flags(8), ProcessorMask(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUpdateHvProcessorFeatures -InputData ([ordered]@{
        Flags         = [uint64]0
        ProcessorMask = [uint64]0
    })
    Write-HvResult "HvCallUpdateHvProcessorFeatures" 0x0005 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSwitchAliasMap {
    <# .SYNOPSIS HvCallSwitchAliasMap (0x0006). Input: { VpIndex(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSwitchAliasMap -InputData ([ordered]@{
        VpIndex = [uint32]0
    })
    Write-HvResult "HvCallSwitchAliasMap" 0x0006 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUpdateMicrocode {
    <# .SYNOPSIS HvCallUpdateMicrocode (0x0007). Input: { PowerState(4), Pad(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUpdateMicrocode -InputData ([ordered]@{
        PowerState = [uint32]0
        Pad        = [uint32]0
    })
    Write-HvResult "HvCallUpdateMicrocode" 0x0007 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region VTL / IPI / flush-ex / patching (0x0008 – 0x001C)
# ==============================================================================

function Example-HvCallNotifyLongSpinWait {
    <# .SYNOPSIS HvCallNotifyLongSpinWait (0x0008) — simple, no input. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallNotifyLongSpinWait
    Write-HvResult "HvCallNotifyLongSpinWait" 0x0008 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallParkedVirtualProcessors {
    <# .SYNOPSIS HvCallParkedVirtualProcessors (0x0009). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallParkedVirtualProcessors -OutputSize 8
    Write-HvResult "HvCallParkedVirtualProcessors" 0x0009 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallInvokeHypervisorDebugger {
    <# .SYNOPSIS HvCallInvokeHypervisorDebugger (0x000A) — triggers hypervisor debugger break. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallInvokeHypervisorDebugger
    Write-HvResult "HvCallInvokeHypervisorDebugger" 0x000A $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSendSyntheticClusterIpi {
    <# .SYNOPSIS HvCallSendSyntheticClusterIpi (0x000B). Input: { Vector(4), Pad(4), ProcessorMask(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSendSyntheticClusterIpi -InputData ([ordered]@{
        Vector        = [uint32]0
        Pad           = [uint32]0
        ProcessorMask = [uint64]0
    })
    Write-HvResult "HvCallSendSyntheticClusterIpi" 0x000B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallModifyVtlProtectionMask {
    <# .SYNOPSIS HvCallModifyVtlProtectionMask (0x000C) — rep, set VTL page protection. Input: Header { PartitionId(8), MapFlags(4), TargetVtl(4) } + Rep { GpaPageNumber(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $gpaPage = if ($ctx.PhysAddr) { [uint64]($ctx.PhysAddr -shr 12) } else { [uint64]0 }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallModifyVtlProtectionMask -InputData ([ordered]@{
        PartitionId   = [uint64]$ctx.PartitionId
        MapFlags      = [uint32]0x07  # RWX
        TargetVtl     = [uint32]0
        GpaPageNumber = [uint64]$gpaPage
    }) -CountOfElements 1
    Write-HvResult "HvCallModifyVtlProtectionMask" 0x000C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallEnablePartitionVtl {
    <# .SYNOPSIS HvCallEnablePartitionVtl (0x000D). Input: { PartitionId(8), TargetVtl(4), Flags(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallEnablePartitionVtl -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
        TargetVtl   = [uint32]1
        Flags       = [uint32]0
    })
    Write-HvResult "HvCallEnablePartitionVtl" 0x000D $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDisablePartitionVtl {
    <# .SYNOPSIS HvCallDisablePartitionVtl (0x000E). Input: { PartitionId(8), TargetVtl(4), Pad(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDisablePartitionVtl -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
        TargetVtl   = [uint32]1
        Pad         = [uint32]0
    })
    Write-HvResult "HvCallDisablePartitionVtl" 0x000E $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallEnableVpVtl {
    <# .SYNOPSIS HvCallEnableVpVtl (0x000F). Input: { PartitionId(8), VpIndex(4), TargetVtl(4), VtlEntryContext(varies) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallEnableVpVtl -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
        VpIndex     = [uint32]0
        TargetVtl   = [uint32]1
    })
    Write-HvResult "HvCallEnableVpVtl" 0x000F $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDisableVpVtl {
    <# .SYNOPSIS HvCallDisableVpVtl (0x0010). Input: { PartitionId(8), VpIndex(4), TargetVtl(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDisableVpVtl -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
        VpIndex     = [uint32]0
        TargetVtl   = [uint32]1
    })
    Write-HvResult "HvCallDisableVpVtl" 0x0010 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallVtlCall {
    <# .SYNOPSIS HvCallVtlCall (0x0011) — transition to higher VTL. Simple, no input page. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallVtlCall
    Write-HvResult "HvCallVtlCall" 0x0011 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallVtlReturn {
    <# .SYNOPSIS HvCallVtlReturn (0x0012) — return from higher VTL. Simple, no input page. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallVtlReturn
    Write-HvResult "HvCallVtlReturn" 0x0012 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushVirtualAddressSpaceEx {
    <# .SYNOPSIS HvCallFlushVirtualAddressSpaceEx (0x0013). Input: { AddressSpace(8), Flags(8), ProcessorSet(variable) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushVirtualAddressSpaceEx -InputData ([ordered]@{
        AddressSpace  = [uint64]0
        Flags         = [uint64]0x0002
        ProcessorSet0 = [uint64]::MaxValue
        ProcessorSet1 = [uint64]0
    })
    Write-HvResult "HvCallFlushVirtualAddressSpaceEx" 0x0013 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushVirtualAddressListEx {
    <# .SYNOPSIS HvCallFlushVirtualAddressListEx (0x0014) — rep. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushVirtualAddressListEx -InputData ([ordered]@{
        AddressSpace  = [uint64]0
        Flags         = [uint64]0
        ProcessorSet0 = [uint64]::MaxValue
        ProcessorSet1 = [uint64]0
        GvaPage0      = [uint64]0
    }) -CountOfElements 1
    Write-HvResult "HvCallFlushVirtualAddressListEx" 0x0014 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSendSyntheticClusterIpiEx {
    <# .SYNOPSIS HvCallSendSyntheticClusterIpiEx (0x0015). Input: { Vector(4), Pad(4), ProcessorSet(variable) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSendSyntheticClusterIpiEx -InputData ([ordered]@{
        Vector        = [uint32]0
        Pad           = [uint32]0
        ProcessorSet0 = [uint64]0
        ProcessorSet1 = [uint64]0
    })
    Write-HvResult "HvCallSendSyntheticClusterIpiEx" 0x0015 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallQueryImageInfo {
    <# .SYNOPSIS HvCallQueryImageInfo (0x0016) — hypervisor patching. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallQueryImageInfo -OutputSize 4096
    Write-HvResult "HvCallQueryImageInfo" 0x0016 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallMapImagePages {
    <# .SYNOPSIS HvCallMapImagePages (0x0017) — hypervisor patching. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapImagePages -InputData ([byte[]]::new(32))
    Write-HvResult "HvCallMapImagePages" 0x0017 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCommitPatch {
    <# .SYNOPSIS HvCallCommitPatch (0x0018) — hypervisor patching. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCommitPatch
    Write-HvResult "HvCallCommitPatch" 0x0018 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSyncContext {
    <# .SYNOPSIS HvCallSyncContext (0x0019) — undocumented. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSyncContext -InputData ([byte[]]::new(16))
    Write-HvResult "HvCallSyncContext" 0x0019 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSyncContextEx {
    <# .SYNOPSIS HvCallSyncContextEx (0x001A) — undocumented. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSyncContextEx -InputData ([byte[]]::new(16))
    Write-HvResult "HvCallSyncContextEx" 0x001A $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetPerfRegister {
    <# .SYNOPSIS HvCallSetPerfRegister (0x001B) — undocumented, performance register. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetPerfRegister -InputData ([ordered]@{
        RegisterIndex = [uint32]0
        Pad           = [uint32]0
        Value         = [uint64]0
    })
    Write-HvResult "HvCallSetPerfRegister" 0x001B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetPerfRegister {
    <# .SYNOPSIS HvCallGetPerfRegister (0x001C) — undocumented, performance register. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetPerfRegister -InputData ([ordered]@{
        RegisterIndex = [uint32]0
        Pad           = [uint32]0
    }) -OutputSize 8
    Write-HvResult "HvCallGetPerfRegister" 0x001C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Partition management (0x0040 – 0x0047)
# ==============================================================================

function Example-HvCallCreatePartition {
    <# .SYNOPSIS HvCallCreatePartition (0x0040). Input: { Flags(8), ProximityDomainInfo(8) }. Output: { NewPartitionId(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreatePartition -InputData ([ordered]@{
        Flags              = [uint64]0
        ProximityDomainInfo = [uint64]0
    }) -OutputSize 8
    $extra = ""
    if ($r.Ok -and $r.OutputBytes.Length -ge 8) { $extra = "NewPartitionId={0}" -f [BitConverter]::ToUInt64($r.OutputBytes, 0) }
    Write-HvResult "HvCallCreatePartition" 0x0040 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallInitializePartition {
    <# .SYNOPSIS HvCallInitializePartition (0x0041). Input: { PartitionId(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallInitializePartition -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
    })
    Write-HvResult "HvCallInitializePartition" 0x0041 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFinalizePartition {
    <# .SYNOPSIS HvCallFinalizePartition (0x0042). Input: { PartitionId(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFinalizePartition -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
    })
    Write-HvResult "HvCallFinalizePartition" 0x0042 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeletePartition {
    <# .SYNOPSIS HvCallDeletePartition (0x0043). Input: { PartitionId(8) } — NOT safe to run on active VM! #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    # Pass invalid ID (0) to avoid deleting a real partition
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeletePartition -InputData ([ordered]@{
        PartitionId = [uint64]0
    })
    Write-HvResult "HvCallDeletePartition" 0x0043 $r.Ok "(safe: PartitionId=0)"
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetPartitionProperty {
    <# .SYNOPSIS HvCallGetPartitionProperty (0x0044). Input: { PartitionId(8), PropertyCode(4), Pad(4) }. Output: { PropertyValue(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    # PropertyCode 0x10003 = ProcessorCount
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetPartitionProperty -InputData ([ordered]@{
        PartitionId  = [uint64]$ctx.PartitionId
        PropertyCode = [uint32]0x10003
        Pad          = [uint32]0
    }) -OutputSize 8
    $extra = ""
    if ($r.Ok -and $r.OutputBytes.Length -ge 8) { $extra = "Value={0}" -f [BitConverter]::ToUInt64($r.OutputBytes, 0) }
    Write-HvResult "HvCallGetPartitionProperty" 0x0044 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetPartitionProperty {
    <# .SYNOPSIS HvCallSetPartitionProperty (0x0045). Input: { PartitionId(8), PropertyCode(4), Pad(4), PropertyValue(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetPartitionProperty -InputData ([ordered]@{
        PartitionId   = [uint64]$ctx.PartitionId
        PropertyCode  = [uint32]0
        Pad           = [uint32]0
        PropertyValue = [uint64]0
    })
    Write-HvResult "HvCallSetPartitionProperty" 0x0045 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetPartitionId {
    <# .SYNOPSIS HvCallGetPartitionId (0x0046) — typed wrapper. Output: { PartitionId(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HvCallGetPartitionId
    $extra = if ($r.Ok) { "PartitionId={0}" -f $r.PartitionId } else { "" }
    Write-HvResult "HvCallGetPartitionId" 0x0046 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetNextChildPartition {
    <# .SYNOPSIS HvCallGetNextChildPartition (0x0047). Input: { ParentId(8), PreviousChildId(8) }. Output: { NextChildId(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetNextChildPartition -InputData ([ordered]@{
        ParentId        = [uint64]$ctx.PartitionId
        PreviousChildId = [uint64]0
    }) -OutputSize 8
    $extra = ""
    if ($r.Ok -and $r.OutputBytes.Length -ge 8) { $extra = "NextChildId={0}" -f [BitConverter]::ToUInt64($r.OutputBytes, 0) }
    Write-HvResult "HvCallGetNextChildPartition" 0x0047 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Memory management (0x0048 – 0x004C)
# ==============================================================================

function Example-HvCallDepositMemory {
    <# .SYNOPSIS HvCallDepositMemory (0x0048) — rep. Input: { PartitionId(8) } + Rep { GpaPageNumber(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDepositMemory -InputData ([ordered]@{
        PartitionId   = [uint64]$ctx.PartitionId
        GpaPageNumber = [uint64]0
    }) -CountOfElements 1
    Write-HvResult "HvCallDepositMemory" 0x0048 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallWithdrawMemory {
    <# .SYNOPSIS HvCallWithdrawMemory (0x0049) — rep. Input: { PartitionId(8), ProximityDomainInfo(8) }. Output: { GpaPageList[] } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallWithdrawMemory -InputData ([ordered]@{
        PartitionId         = [uint64]$ctx.PartitionId
        ProximityDomainInfo = [uint64]0
    }) -OutputSize 4096 -CountOfElements 1
    Write-HvResult "HvCallWithdrawMemory" 0x0049 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetMemoryBalance {
    <# .SYNOPSIS HvCallGetMemoryBalance (0x004A). Input: { PartitionId(8), ProximityDomainInfo(8) }. Output: { PagesAvailable(8), PagesInUse(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetMemoryBalance -InputData ([ordered]@{
        PartitionId         = [uint64]$ctx.PartitionId
        ProximityDomainInfo = [uint64]0
    }) -OutputSize 16
    $extra = ""
    if ($r.Ok -and $r.OutputBytes.Length -ge 16) {
        $avail = [BitConverter]::ToUInt64($r.OutputBytes, 0)
        $inUse = [BitConverter]::ToUInt64($r.OutputBytes, 8)
        $extra = "Available={0}, InUse={1}" -f $avail, $inUse
    }
    Write-HvResult "HvCallGetMemoryBalance" 0x004A $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallMapGpaPages {
    <# .SYNOPSIS HvCallMapGpaPages (0x004B) — rep. Input: { TargetPartitionId(8), TargetGpaBase(8), MapFlags(8) } + Rep { SourceGpaPage(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapGpaPages -InputData ([ordered]@{
        TargetPartitionId = [uint64]$ctx.PartitionId
        TargetGpaBase     = [uint64]0
        MapFlags          = [uint64]0
        SourceGpaPage     = [uint64]0
    }) -CountOfElements 1
    Write-HvResult "HvCallMapGpaPages" 0x004B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnmapGpaPages {
    <# .SYNOPSIS HvCallUnmapGpaPages (0x004C) — rep. Input: { TargetPartitionId(8), TargetGpaBase(8) } + Rep { GpaPage(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnmapGpaPages -InputData ([ordered]@{
        TargetPartitionId = [uint64]$ctx.PartitionId
        TargetGpaBase     = [uint64]0
    }) -CountOfElements 1
    Write-HvResult "HvCallUnmapGpaPages" 0x004C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Intercept / VP / Registers (0x004D – 0x0054)
# ==============================================================================

function Example-HvCallInstallIntercept {
    <# .SYNOPSIS HvCallInstallIntercept (0x004D). Input: { PartitionId(8), AccessType(4), InterceptType(4), InterceptParameter(16) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallInstallIntercept -InputData ([ordered]@{
        PartitionId        = [uint64]$ctx.PartitionId
        AccessType         = [uint32]0
        InterceptType      = [uint32]0
        InterceptParameter = [uint64]0
        InterceptParam2    = [uint64]0
    })
    Write-HvResult "HvCallInstallIntercept" 0x004D $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCreateVp {
    <# .SYNOPSIS HvCallCreateVp (0x004E). Input: { PartitionId(8), VpIndex(4), Pad(4), ProximityDomainInfo(8), Flags(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreateVp -InputData ([ordered]@{
        PartitionId         = [uint64]$ctx.PartitionId
        VpIndex             = [uint32]0xFF
        Pad                 = [uint32]0
        ProximityDomainInfo = [uint64]0
        Flags               = [uint64]0
    })
    Write-HvResult "HvCallCreateVp" 0x004E $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeleteVp {
    <# .SYNOPSIS HvCallDeleteVp (0x004F). Input: { PartitionId(8), VpIndex(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    # Use invalid VP index to avoid damage
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeleteVp -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
        VpIndex     = [uint32]0xFF
    })
    Write-HvResult "HvCallDeleteVp" 0x004F $r.Ok "(safe: VpIndex=0xFF)"
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetVpRegisters {
    <# .SYNOPSIS HvCallGetVpRegisters (0x0050) — typed wrapper, reads RIP/RSP/CR3. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HvCallGetVpRegisters -PartitionId $ctx.PartitionId -VpIndex 0 `
        -RegisterNames @([uint32]0x00020000, [uint32]0x00020002, [uint32]0x00020014)
    $extra = ""
    if ($r.Ok) { $extra = "RIP=0x{0:X}, RSP=0x{1:X}, CR3=0x{2:X}" -f $r.Values[0], $r.Values[1], $r.Values[2] }
    Write-HvResult "HvCallGetVpRegisters" 0x0050 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetVpRegisters {
    <# .SYNOPSIS HvCallSetVpRegisters (0x0051) — typed wrapper, DR0 round-trip. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $DR0 = [uint32]0x00020017
    $read = Invoke-HvCallGetVpRegisters -PartitionId $ctx.PartitionId -VpIndex 0 -RegisterNames @($DR0)
    $ok = $false
    if ($read.Ok) {
        $write = Invoke-HvCallSetVpRegisters -PartitionId $ctx.PartitionId -VpIndex 0 `
            -Registers @(@{ Name = $DR0; Value = $read.Values[0] })
        $ok = $write.Ok
    }
    Write-HvResult "HvCallSetVpRegisters" 0x0051 $ok "DR0=0x$($read.Values[0].ToString('X'))"
    Close-HvlibPartition -handle $ctx.Handle
    return $read
}

function Example-HvCallTranslateVirtualAddress {
    <# .SYNOPSIS HvCallTranslateVirtualAddress (0x0052) — typed wrapper. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HvCallTranslateVirtualAddress -PartitionId $ctx.PartitionId -GvaPage $ctx.SymVA
    $extra = if ($r.Ok) { "GpaPage=0x{0:X}" -f $r.GpaPage } else { "" }
    Write-HvResult "HvCallTranslateVirtualAddress" 0x0052 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallReadGpa {
    <# .SYNOPSIS HvCallReadGpa (0x0053) — typed wrapper, 16 bytes from known GPA. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HvCallReadGpa -PartitionId $ctx.PartitionId -BaseGpa $ctx.PhysAddr -ByteCount 16
    $extra = ""
    if ($r.Ok) { $extra = "Data=" + (($r.Data | ForEach-Object { "{0:X2}" -f $_ }) -join ' ') }
    Write-HvResult "HvCallReadGpa" 0x0053 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallWriteGpa {
    <# .SYNOPSIS HvCallWriteGpa (0x0054) — typed wrapper, safe round-trip via nt!NtBuildNumber (writable data). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    # Use nt!NtBuildNumber (kernel data section, writable) instead of code pages
    $symName = "nt!NtBuildNumber"
    $symVA = Get-HvlibSymbolAddressDirect $ctx.Handle $symName
    if (-not $symVA -or $symVA -eq 0) {
        Write-HvResult "HvCallWriteGpa" 0x0054 $false "symbol '$symName' not found"
        Close-HvlibPartition -handle $ctx.Handle
        return
    }
    $gpa = Get-HvlibPhysicalAddress -PartitionHandle $ctx.Handle -VirtualAddress $symVA

    # Read → Write same bytes → Read again (non-destructive round-trip)
    $read = Invoke-HvCallReadGpa -PartitionId $ctx.PartitionId -BaseGpa $gpa -ByteCount 8
    $ok = $false
    if ($read.Ok -and $read.AccessResult -eq 0) {
        $w = Invoke-HvCallWriteGpa -PartitionId $ctx.PartitionId -BaseGpa $gpa -Data $read.Data
        $ok = $w.Ok -and $w.AccessResult -eq 0
    }

    $extra = "GPA=0x{0:X}, {1}, AR={2}" -f $gpa, $symName, $(if ($ok) {0} else {"write-protected"})
    Write-HvResult "HvCallWriteGpa" 0x0054 $ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $read
}

#endregion


# ==============================================================================
#region Interrupts (0x0055 – 0x0056)
# ==============================================================================

function Example-HvCallAssertVirtualInterruptDeprecated {
    <# .SYNOPSIS HvCallAssertVirtualInterruptDeprecated (0x0055). Input: { TargetPartition(8), InterruptControl(8), DestinationAddress(8), RequestedVector(4), Pad(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAssertVirtualInterruptDeprecated -InputData ([ordered]@{
        TargetPartition    = [uint64]$ctx.PartitionId
        InterruptControl   = [uint64]0
        DestinationAddress = [uint64]0
        RequestedVector    = [uint32]0
        Pad                = [uint32]0
    })
    Write-HvResult "HvCallAssertVirtualInterruptDeprecated" 0x0055 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallClearVirtualInterrupt {
    <# .SYNOPSIS HvCallClearVirtualInterrupt (0x0056). Input: { TargetPartition(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallClearVirtualInterrupt -InputData ([ordered]@{
        TargetPartition = [uint64]$ctx.PartitionId
    })
    Write-HvResult "HvCallClearVirtualInterrupt" 0x0056 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Ports / messaging (0x0057 – 0x005D)
# ==============================================================================

function Example-HvCallCreatePortDeprecated {
    <# .SYNOPSIS HvCallCreatePortDeprecated (0x0057). Input: { PortPartition(8), PortId(4), Pad(4), ConnectionPartition(8), PortInfo(32) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreatePortDeprecated -InputData ([ordered]@{
        PortPartition       = [uint64]$ctx.PartitionId
        PortId              = [uint32]1
        Pad                 = [uint32]0
        ConnectionPartition = [uint64]$ctx.PartitionId
        PortInfo0           = [uint64]0
        PortInfo1           = [uint64]0
        PortInfo2           = [uint64]0
        PortInfo3           = [uint64]0
    })
    Write-HvResult "HvCallCreatePortDeprecated" 0x0057 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeletePort {
    <# .SYNOPSIS HvCallDeletePort (0x0058). Input: { PortPartition(8), PortId(4), Pad(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeletePort -InputData ([ordered]@{
        PortPartition = [uint64]$ctx.PartitionId
        PortId        = [uint32]0
        Pad           = [uint32]0
    })
    Write-HvResult "HvCallDeletePort" 0x0058 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallConnectPortDeprecated {
    <# .SYNOPSIS HvCallConnectPortDeprecated (0x0059). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallConnectPortDeprecated -InputData ([byte[]]::new(56))
    Write-HvResult "HvCallConnectPortDeprecated" 0x0059 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetPortProperty {
    <# .SYNOPSIS HvCallGetPortProperty (0x005A). Input: { PortPartition(8), PortId(4), Pad(4), PropertyCode(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetPortProperty -InputData ([ordered]@{
        PortPartition = [uint64]$ctx.PartitionId
        PortId        = [uint32]0
        Pad           = [uint32]0
        PropertyCode  = [uint32]0
        Pad2          = [uint32]0
    }) -OutputSize 8
    Write-HvResult "HvCallGetPortProperty" 0x005A $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDisconnectPort {
    <# .SYNOPSIS HvCallDisconnectPort (0x005B). Input: { ConnectionPartition(8), ConnectionId(4), Pad(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDisconnectPort -InputData ([ordered]@{
        ConnectionPartition = [uint64]$ctx.PartitionId
        ConnectionId        = [uint32]0
        Pad                 = [uint32]0
    })
    Write-HvResult "HvCallDisconnectPort" 0x005B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPostMessage {
    <# .SYNOPSIS HvCallPostMessage (0x005C) — typed wrapper. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HvCallPostMessage -ConnectionId 1 -MessageType 1 -Payload @(0x48, 0x56)
    Write-HvResult "HvCallPostMessage" 0x005C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSignalEvent {
    <# .SYNOPSIS HvCallSignalEvent (0x005D) — typed wrapper. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HvCallSignalEvent -ConnectionId 1 -FlagNumber 0
    Write-HvResult "HvCallSignalEvent" 0x005D $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Partition state (0x005E – 0x005F)
# ==============================================================================

function Example-HvCallSavePartitionState {
    <# .SYNOPSIS HvCallSavePartitionState (0x005E). Input: { PartitionId(8), Flags(8) }. Output: { SaveDataCount(4), SaveState(4), SaveData[4080] } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSavePartitionState -InputData ([ordered]@{
        PartitionId = [uint64]$ctx.PartitionId
        Flags       = [uint64]0
    }) -OutputSize 4096
    Write-HvResult "HvCallSavePartitionState" 0x005E $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRestorePartitionState {
    <# .SYNOPSIS HvCallRestorePartitionState (0x005F). Input: { PartitionId(8), Flags(8), RestoreDataCount(4), RestoreData[4080] } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRestorePartitionState -InputData ([ordered]@{
        PartitionId      = [uint64]$ctx.PartitionId
        Flags            = [uint64]0
        RestoreDataCount = [uint32]0
        Pad              = [uint32]0
    }) -OutputSize 8
    Write-HvResult "HvCallRestorePartitionState" 0x005F $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Event logging (0x0060 – 0x0068)
# ==============================================================================

function Example-HvCallInitializeEventLogBufferGroup {
    <# .SYNOPSIS 0x0060. Input: { EventLogType(4), MaxBufferCount(4), BufferSizeInPages(4), Threshold(4), TimeBasis(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallInitializeEventLogBufferGroup -InputData ([ordered]@{
        EventLogType     = [uint32]0; MaxBufferCount = [uint32]1
        BufferSizeInPages = [uint32]1; Threshold = [uint32]0; TimeBasis = [uint32]0; Pad = [uint32]0
    })
    Write-HvResult "HvCallInitializeEventLogBufferGroup" 0x0060 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFinalizeEventLogBufferGroup {
    <# .SYNOPSIS 0x0061. Input: { EventLogType(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFinalizeEventLogBufferGroup -InputData ([ordered]@{ EventLogType = [uint32]0; Pad = [uint32]0 })
    Write-HvResult "HvCallFinalizeEventLogBufferGroup" 0x0061 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCreateEventLogBuffer {
    <# .SYNOPSIS 0x0062. Input: { EventLogType(4), BufferIndex(4), ProximityInfo(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreateEventLogBuffer -InputData ([ordered]@{
        EventLogType = [uint32]0; BufferIndex = [uint32]0; ProximityInfo = [uint64]0
    })
    Write-HvResult "HvCallCreateEventLogBuffer" 0x0062 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeleteEventLogBuffer {
    <# .SYNOPSIS 0x0063. Input: { EventLogType(4), BufferIndex(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeleteEventLogBuffer -InputData ([ordered]@{ EventLogType = [uint32]0; BufferIndex = [uint32]0 })
    Write-HvResult "HvCallDeleteEventLogBuffer" 0x0063 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallMapEventLogBuffer {
    <# .SYNOPSIS 0x0064. Input: { EventLogType(4), BufferIndex(4) }. Output: { GpaPageNumbers[512] } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapEventLogBuffer -InputData ([ordered]@{ EventLogType = [uint32]0; BufferIndex = [uint32]0 }) -OutputSize 4096
    Write-HvResult "HvCallMapEventLogBuffer" 0x0064 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnmapEventLogBuffer {
    <# .SYNOPSIS 0x0065. Input: { EventLogType(4), BufferIndex(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnmapEventLogBuffer -InputData ([ordered]@{ EventLogType = [uint32]0; BufferIndex = [uint32]0 })
    Write-HvResult "HvCallUnmapEventLogBuffer" 0x0065 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetEventLogGroupSources {
    <# .SYNOPSIS 0x0066. Input: { EventLogType(4), Pad(4), EnableFlags(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetEventLogGroupSources -InputData ([ordered]@{ EventLogType = [uint32]0; Pad = [uint32]0; EnableFlags = [uint64]0 })
    Write-HvResult "HvCallSetEventLogGroupSources" 0x0066 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallReleaseEventLogBuffer {
    <# .SYNOPSIS 0x0067. Input: { EventLogType(4), BufferIndex(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallReleaseEventLogBuffer -InputData ([ordered]@{ EventLogType = [uint32]0; BufferIndex = [uint32]0 })
    Write-HvResult "HvCallReleaseEventLogBuffer" 0x0067 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushEventLogBuffer {
    <# .SYNOPSIS 0x0068. Input: { EventLogType(4), VpIndex(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushEventLogBuffer -InputData ([ordered]@{ EventLogType = [uint32]0; VpIndex = [uint32]0 })
    Write-HvResult "HvCallFlushEventLogBuffer" 0x0068 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Debugging (0x0069 – 0x006B)
# ==============================================================================

function Example-HvCallPostDebugData {
    <# .SYNOPSIS 0x0069. Input: { Count(4), Options(4), Data[...] }. Output: { PendingCount(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPostDebugData -InputData ([ordered]@{
        Count = [uint32]0; Options = [uint32]0
    }) -OutputSize 4
    Write-HvResult "HvCallPostDebugData" 0x0069 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRetrieveDebugData {
    <# .SYNOPSIS 0x006A. Input: { Count(4), Options(4), Timeout(8) }. Output: { RetrievedCount(4), RemainingCount(4), Data[...] } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRetrieveDebugData -InputData ([ordered]@{
        Count = [uint32]0; Options = [uint32]0; Timeout = [uint64]0
    }) -OutputSize 4096
    Write-HvResult "HvCallRetrieveDebugData" 0x006A $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallResetDebugSession {
    <# .SYNOPSIS 0x006B. Input: { Options(4) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallResetDebugSession -InputData ([ordered]@{ Options = [uint32]0; Pad = [uint32]0 })
    Write-HvResult "HvCallResetDebugSession" 0x006B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Statistics (0x006C – 0x006D)
# ==============================================================================

function Example-HvCallMapStatsPage {
    <# .SYNOPSIS 0x006C. Input: { StatsType(4), Pad(4), ObjectIdentity(16), MapLocation(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapStatsPage -InputData ([ordered]@{
        StatsType = [uint32]0; Pad = [uint32]0
        ObjId0 = [uint64]0; ObjId1 = [uint64]0
        MapLocation = [uint64]0
    })
    Write-HvResult "HvCallMapStatsPage" 0x006C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnmapStatsPage {
    <# .SYNOPSIS 0x006D. Input: { StatsType(4), Pad(4), ObjectIdentity(16) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnmapStatsPage -InputData ([ordered]@{
        StatsType = [uint32]0; Pad = [uint32]0; ObjId0 = [uint64]0; ObjId1 = [uint64]0
    })
    Write-HvResult "HvCallUnmapStatsPage" 0x006D $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region V1 extended / test (0x006E – 0x0075)
# ==============================================================================

function Example-HvCallMapSparseGpaPages {
    <# .SYNOPSIS 0x006E — rep. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapSparseGpaPages -InputData ([ordered]@{
        TargetPartitionId = [uint64]$ctx.PartitionId; TargetGpaBase = [uint64]0; MapFlags = [uint64]0
    })
    Write-HvResult "HvCallMapSparseGpaPages" 0x006E $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetSystemProperty {
    <# .SYNOPSIS 0x006F. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetSystemProperty -InputData ([byte[]]::new(16))
    Write-HvResult "HvCallSetSystemProperty" 0x006F $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetPortProperty {
    <# .SYNOPSIS 0x0070. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetPortProperty -InputData ([byte[]]::new(32))
    Write-HvResult "HvCallSetPortProperty" 0x0070 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallOutputDebugCharacter {
    <# .SYNOPSIS 0x0071. Input: { Character(2) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallOutputDebugCharacter -InputData ([ordered]@{
        Character = [uint16]0x41  # 'A'
        Pad       = [uint16]0
        Pad2      = [uint32]0
    })
    Write-HvResult "HvCallOutputDebugCharacter" 0x0071 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallEchoIncrement {
    <# .SYNOPSIS 0x0072 — test: returns input+1. Input: { Value(8) }. Output: { Value(8) } #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallEchoIncrement -InputData ([ordered]@{ Value = [uint64]41 }) -OutputSize 8
    $extra = ""
    if ($r.Ok -and $r.OutputBytes.Length -ge 8) {
        $out = [BitConverter]::ToUInt64($r.OutputBytes, 0)
        $extra = "In=41, Out={0} ({1})" -f $out, $(if ($out -eq 42) {"CORRECT"} else {"MISMATCH"})
    }
    Write-HvResult "HvCallEchoIncrement" 0x0072 $r.Ok $extra
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPerfNop {
    <# .SYNOPSIS 0x0073 — no-op, latency measurement. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPerfNop -OutputSize 0
    $sw.Stop()
    Write-HvResult "HvCallPerfNop" 0x0073 $r.Ok ("{0:N3} ms" -f $sw.Elapsed.TotalMilliseconds)
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPerfNopInput {
    <# .SYNOPSIS 0x0074 — no-op with input page. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPerfNopInput -InputData ([byte[]]::new(8))
    Write-HvResult "HvCallPerfNopInput" 0x0074 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPerfNopOutput {
    <# .SYNOPSIS 0x0075 — no-op with output page. #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }
    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPerfNopOutput -OutputSize 8
    Write-HvResult "HvCallPerfNopOutput" 0x0075 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region V2 logical processor / NUMA / system (0x0076 – 0x007B)
# ==============================================================================

function Example-HvCallAddLogicalProcessor {
    <# .SYNOPSIS HvCallAddLogicalProcessor (0x0076). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAddLogicalProcessor -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallAddLogicalProcessor" 0x0076 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRemoveLogicalProcessor {
    <# .SYNOPSIS HvCallRemoveLogicalProcessor (0x0077). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRemoveLogicalProcessor -InputData ([ordered]@{ LpIndex=[uint32]0xFF; Pad=[uint32]0 })

    Write-HvResult "HvCallRemoveLogicalProcessor" 0x0077 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallQueryNumaDistance {
    <# .SYNOPSIS HvCallQueryNumaDistance (0x0078). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallQueryNumaDistance -InputData ([ordered]@{ SourceNode=[uint32]0; DestNode=[uint32]0 }) -OutputSize 4

    Write-HvResult "HvCallQueryNumaDistance" 0x0078 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetLogicalProcessorProperty {
    <# .SYNOPSIS HvCallSetLogicalProcessorProperty (0x0079). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetLogicalProcessorProperty -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallSetLogicalProcessorProperty" 0x0079 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetLogicalProcessorProperty {
    <# .SYNOPSIS HvCallGetLogicalProcessorProperty (0x007A). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetLogicalProcessorProperty -InputData ([byte[]]::new(16)) -OutputSize 16

    Write-HvResult "HvCallGetLogicalProcessorProperty" 0x007A $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetSystemProperty {
    <# .SYNOPSIS HvCallGetSystemProperty (0x007B). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetSystemProperty -InputData ([byte[]]::new(16)) -OutputSize 4096

    Write-HvResult "HvCallGetSystemProperty" 0x007B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Device interrupts (0x007C - 0x0080)
# ==============================================================================

function Example-HvCallMapDeviceInterrupt {
    <# .SYNOPSIS HvCallMapDeviceInterrupt (0x007C). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapDeviceInterrupt -InputData ([byte[]]::new(48)) -OutputSize 8

    Write-HvResult "HvCallMapDeviceInterrupt" 0x007C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnmapDeviceInterrupt {
    <# .SYNOPSIS HvCallUnmapDeviceInterrupt (0x007D). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnmapDeviceInterrupt -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallUnmapDeviceInterrupt" 0x007D $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRetargetDeviceInterrupt {
    <# .SYNOPSIS HvCallRetargetDeviceInterrupt (0x007E). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRetargetDeviceInterrupt -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallRetargetDeviceInterrupt" 0x007E $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRetargetRootDeviceInterrupt {
    <# .SYNOPSIS HvCallRetargetRootDeviceInterrupt (0x007F). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRetargetRootDeviceInterrupt -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallRetargetRootDeviceInterrupt" 0x007F $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAssertDeviceInterrupt {
    <# .SYNOPSIS HvCallAssertDeviceInterrupt (0x0080). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAssertDeviceInterrupt -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallAssertDeviceInterrupt" 0x0080 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Device / power / MCA (0x0082 - 0x008F)
# ==============================================================================

function Example-HvCallAttachDevice {
    <# .SYNOPSIS HvCallAttachDevice (0x0082). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAttachDevice -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; DeviceId=[uint64]0 })

    Write-HvResult "HvCallAttachDevice" 0x0082 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDetachDevice {
    <# .SYNOPSIS HvCallDetachDevice (0x0083). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDetachDevice -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; DeviceId=[uint64]0 })

    Write-HvResult "HvCallDetachDevice" 0x0083 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallEnterSleepState {
    <# .SYNOPSIS HvCallEnterSleepState (0x0084). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallEnterSleepState -InputData ([ordered]@{ SleepState=[uint32]0; Pad=[uint32]0 })

    Write-HvResult "HvCallEnterSleepState" 0x0084 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallNotifyStandbyTransition {
    <# .SYNOPSIS HvCallNotifyStandbyTransition (0x0085). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallNotifyStandbyTransition -InputData ([ordered]@{ Entering=[uint32]0; Pad=[uint32]0 })

    Write-HvResult "HvCallNotifyStandbyTransition" 0x0085 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPrepareForHibernate {
    <# .SYNOPSIS HvCallPrepareForHibernate (0x0086). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPrepareForHibernate -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallPrepareForHibernate" 0x0086 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallNotifyPartitionEvent {
    <# .SYNOPSIS HvCallNotifyPartitionEvent (0x0087). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallNotifyPartitionEvent -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        EventType            = [uint32]0
        Pad                  = [uint32]0
    })

    Write-HvResult "HvCallNotifyPartitionEvent" 0x0087 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetLogicalProcessorRegisters {
    <# .SYNOPSIS HvCallGetLogicalProcessorRegisters (0x0088). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetLogicalProcessorRegisters -InputData ([byte[]]::new(16)) -OutputSize 128

    Write-HvResult "HvCallGetLogicalProcessorRegisters" 0x0088 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetLogicalProcessorRegisters {
    <# .SYNOPSIS HvCallSetLogicalProcessorRegisters (0x0089). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetLogicalProcessorRegisters -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallSetLogicalProcessorRegisters" 0x0089 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallQueryAssociatedLpsForMca {
    <# .SYNOPSIS HvCallQueryAssociatedLpsForMca (0x008A). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallQueryAssociatedLpsForMca -InputData ([byte[]]::new(16)) -OutputSize 64

    Write-HvResult "HvCallQueryAssociatedLpsForMca" 0x008A $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallNotifyPortRingEmpty {
    <# .SYNOPSIS HvCallNotifyPortRingEmpty (0x008B). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallNotifyPortRingEmpty -InputData ([ordered]@{ ConnectionId=[uint32]0; Pad=[uint32]0 })

    Write-HvResult "HvCallNotifyPortRingEmpty" 0x008B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallInjectSyntheticMachineCheck {
    <# .SYNOPSIS HvCallInjectSyntheticMachineCheck (0x008C). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallInjectSyntheticMachineCheck -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallInjectSyntheticMachineCheck" 0x008C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallScrubPartition {
    <# .SYNOPSIS HvCallScrubPartition (0x008D). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallScrubPartition -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId })

    Write-HvResult "HvCallScrubPartition" 0x008D $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCollectLivedump {
    <# .SYNOPSIS HvCallCollectLivedump (0x008E). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCollectLivedump -InputData ([byte[]]::new(32)) -OutputSize 4096

    Write-HvResult "HvCallCollectLivedump" 0x008E $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDisableHypervisor {
    <# .SYNOPSIS HvCallDisableHypervisor (0x008F). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDisableHypervisor

    Write-HvResult "HvCallDisableHypervisor" 0x008F $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Sparse GPA / intercept result / assert V2 (0x0090 - 0x009C)
# ==============================================================================

function Example-HvCallModifySparseGpaPages {
    <# .SYNOPSIS HvCallModifySparseGpaPages (0x0090). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallModifySparseGpaPages -InputData ([ordered]@{ TargetPartitionId=[uint64]$ctx.PartitionId; MapFlags=[uint64]0 })

    Write-HvResult "HvCallModifySparseGpaPages" 0x0090 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRegisterInterceptResult {
    <# .SYNOPSIS HvCallRegisterInterceptResult (0x0091). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRegisterInterceptResult -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallRegisterInterceptResult" 0x0091 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnregisterInterceptResult {
    <# .SYNOPSIS HvCallUnregisterInterceptResult (0x0092). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnregisterInterceptResult -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallUnregisterInterceptResult" 0x0092 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetCoverageData {
    <# .SYNOPSIS HvCallGetCoverageData (0x0093). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetCoverageData -InputData ([byte[]]::new(8)) -OutputSize 4096

    Write-HvResult "HvCallGetCoverageData" 0x0093 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAssertVirtualInterrupt {
    <# .SYNOPSIS HvCallAssertVirtualInterrupt (0x0094). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAssertVirtualInterrupt -InputData ([ordered]@{
        TargetPartition      = [uint64]$ctx.PartitionId
        InterruptControl     = [uint64]0
        DestinationAddress   = [uint64]0
        RequestedVector      = [uint32]0
        Pad                  = [uint32]0
    })

    Write-HvResult "HvCallAssertVirtualInterrupt" 0x0094 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCreatePort {
    <# .SYNOPSIS HvCallCreatePort (0x0095). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreatePort -InputData ([byte[]]::new(64))

    Write-HvResult "HvCallCreatePort" 0x0095 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallConnectPort {
    <# .SYNOPSIS HvCallConnectPort (0x0096). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallConnectPort -InputData ([byte[]]::new(64))

    Write-HvResult "HvCallConnectPort" 0x0096 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetSpaPageList {
    <# .SYNOPSIS HvCallGetSpaPageList (0x0097). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetSpaPageList -InputData ([byte[]]::new(16)) -OutputSize 4096

    Write-HvResult "HvCallGetSpaPageList" 0x0097 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallStartVirtualProcessor {
    <# .SYNOPSIS HvCallStartVirtualProcessor (0x0099). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallStartVirtualProcessor -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Pad                  = [uint32]0
    })

    Write-HvResult "HvCallStartVirtualProcessor" 0x0099 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetVpIndexFromApicId {
    <# .SYNOPSIS HvCallGetVpIndexFromApicId (0x009A). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetVpIndexFromApicId -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        ApicId               = [uint32]0
        Pad                  = [uint32]0
    }) -OutputSize 8 -CountOfElements 1

    Write-HvResult "HvCallGetVpIndexFromApicId" 0x009A $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetPowerProperty {
    <# .SYNOPSIS HvCallGetPowerProperty (0x009B). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetPowerProperty -InputData ([byte[]]::new(16)) -OutputSize 8

    Write-HvResult "HvCallGetPowerProperty" 0x009B $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetPowerProperty {
    <# .SYNOPSIS HvCallSetPowerProperty (0x009C). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetPowerProperty -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallSetPowerProperty" 0x009C $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region PASID (0x009D - 0x00A9)
# ==============================================================================

function Example-HvCallCreatePasidSpace {
    <# .SYNOPSIS HvCallCreatePasidSpace (0x009D). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreatePasidSpace -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallCreatePasidSpace" 0x009D $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeletePasidSpace {
    <# .SYNOPSIS HvCallDeletePasidSpace (0x009E). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeletePasidSpace -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallDeletePasidSpace" 0x009E $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetPasidAddressSpace {
    <# .SYNOPSIS HvCallSetPasidAddressSpace (0x009F). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetPasidAddressSpace -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallSetPasidAddressSpace" 0x009F $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushPasidAddressSpace {
    <# .SYNOPSIS HvCallFlushPasidAddressSpace (0x00A0). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushPasidAddressSpace -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallFlushPasidAddressSpace" 0x00A0 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushPasidAddressList {
    <# .SYNOPSIS HvCallFlushPasidAddressList (0x00A1). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushPasidAddressList -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallFlushPasidAddressList" 0x00A1 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAttachPasidSpace {
    <# .SYNOPSIS HvCallAttachPasidSpace (0x00A2). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAttachPasidSpace -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallAttachPasidSpace" 0x00A2 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDetachPasidSpace {
    <# .SYNOPSIS HvCallDetachPasidSpace (0x00A3). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDetachPasidSpace -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallDetachPasidSpace" 0x00A3 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallEnablePasid {
    <# .SYNOPSIS HvCallEnablePasid (0x00A4). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallEnablePasid -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallEnablePasid" 0x00A4 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDisablePasid {
    <# .SYNOPSIS HvCallDisablePasid (0x00A5). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDisablePasid -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallDisablePasid" 0x00A5 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAcknowledgeDevicePageRequest {
    <# .SYNOPSIS HvCallAcknowledgeDevicePageRequest (0x00A6). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAcknowledgeDevicePageRequest -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallAcknowledgeDevicePageRequest" 0x00A6 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCreateDevicePrQueue {
    <# .SYNOPSIS HvCallCreateDevicePrQueue (0x00A7). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreateDevicePrQueue -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallCreateDevicePrQueue" 0x00A7 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeleteDevicePrQueue {
    <# .SYNOPSIS HvCallDeleteDevicePrQueue (0x00A8). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeleteDevicePrQueue -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallDeleteDevicePrQueue" 0x00A8 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetDevicePrqProperty {
    <# .SYNOPSIS HvCallSetDevicePrqProperty (0x00A9). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetDevicePrqProperty -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallSetDevicePrqProperty" 0x00A9 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Physical device / translate-ex / GPA attributes / device domain /
#       CPU groups / memory / GPA commit (0x00AA - 0x00BF)
# ==============================================================================

function Example-HvCallGetPhysicalDeviceProperty {
    <# .SYNOPSIS HvCallGetPhysicalDeviceProperty (0x00AA). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetPhysicalDeviceProperty -InputData ([byte[]]::new(16)) -OutputSize 16

    Write-HvResult "HvCallGetPhysicalDeviceProperty" 0x00AA $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetPhysicalDeviceProperty {
    <# .SYNOPSIS HvCallSetPhysicalDeviceProperty (0x00AB). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetPhysicalDeviceProperty -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallSetPhysicalDeviceProperty" 0x00AB $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallTranslateVirtualAddressEx {
    <# .SYNOPSIS HvCallTranslateVirtualAddressEx (0x00AC). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallTranslateVirtualAddressEx -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Pad                  = [uint32]0
        ControlFlags         = [uint64]0
        GvaPage              = [uint64]$ctx.SymVA
    }) -OutputSize 16

    Write-HvResult "HvCallTranslateVirtualAddressEx" 0x00AC $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCheckForIoIntercept {
    <# .SYNOPSIS HvCallCheckForIoIntercept (0x00AD). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCheckForIoIntercept -InputData ([byte[]]::new(32)) -OutputSize 16

    Write-HvResult "HvCallCheckForIoIntercept" 0x00AD $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetGpaPageAttributes {
    <# .SYNOPSIS HvCallSetGpaPageAttributes (0x00AE). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetGpaPageAttributes -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallSetGpaPageAttributes" 0x00AE $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushGuestPhysicalAddressSpace {
    <# .SYNOPSIS HvCallFlushGuestPhysicalAddressSpace (0x00AF). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushGuestPhysicalAddressSpace -InputData ([ordered]@{ AddressSpace=[uint64]0; Flags=[uint64]0 })

    Write-HvResult "HvCallFlushGuestPhysicalAddressSpace" 0x00AF $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushGuestPhysicalAddressList {
    <# .SYNOPSIS HvCallFlushGuestPhysicalAddressList (0x00B0). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushGuestPhysicalAddressList -InputData ([ordered]@{
        AddressSpace         = [uint64]0
        Flags                = [uint64]0
        GpaPage              = [uint64]0
    }) -CountOfElements 1

    Write-HvResult "HvCallFlushGuestPhysicalAddressList" 0x00B0 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCreateDeviceDomain {
    <# .SYNOPSIS HvCallCreateDeviceDomain (0x00B1). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreateDeviceDomain -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 }) -OutputSize 8

    Write-HvResult "HvCallCreateDeviceDomain" 0x00B1 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAttachDeviceDomain {
    <# .SYNOPSIS HvCallAttachDeviceDomain (0x00B2). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAttachDeviceDomain -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallAttachDeviceDomain" 0x00B2 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallMapDeviceGpaPages {
    <# .SYNOPSIS HvCallMapDeviceGpaPages (0x00B3). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapDeviceGpaPages -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallMapDeviceGpaPages" 0x00B3 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnmapDeviceGpaPages {
    <# .SYNOPSIS HvCallUnmapDeviceGpaPages (0x00B4). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnmapDeviceGpaPages -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallUnmapDeviceGpaPages" 0x00B4 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCreateCpuGroup {
    <# .SYNOPSIS HvCallCreateCpuGroup (0x00B5). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreateCpuGroup -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; CpuGroupId=[uint64]0 })

    Write-HvResult "HvCallCreateCpuGroup" 0x00B5 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeleteCpuGroup {
    <# .SYNOPSIS HvCallDeleteCpuGroup (0x00B6). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeleteCpuGroup -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; CpuGroupId=[uint64]0 })

    Write-HvResult "HvCallDeleteCpuGroup" 0x00B6 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetCpuGroupProperty {
    <# .SYNOPSIS HvCallGetCpuGroupProperty (0x00B7). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetCpuGroupProperty -InputData ([byte[]]::new(24)) -OutputSize 16

    Write-HvResult "HvCallGetCpuGroupProperty" 0x00B7 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetCpuGroupProperty {
    <# .SYNOPSIS HvCallSetCpuGroupProperty (0x00B8). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetCpuGroupProperty -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallSetCpuGroupProperty" 0x00B8 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetCpuGroupAffinity {
    <# .SYNOPSIS HvCallGetCpuGroupAffinity (0x00B9). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetCpuGroupAffinity -InputData ([byte[]]::new(16)) -OutputSize 32

    Write-HvResult "HvCallGetCpuGroupAffinity" 0x00B9 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetNextCpuGroup {
    <# .SYNOPSIS HvCallGetNextCpuGroup (0x00BA). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetNextCpuGroup -InputData ([byte[]]::new(16)) -OutputSize 16

    Write-HvResult "HvCallGetNextCpuGroup" 0x00BA $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetNextCpuGroupPartition {
    <# .SYNOPSIS HvCallGetNextCpuGroupPartition (0x00BB). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetNextCpuGroupPartition -InputData ([byte[]]::new(16)) -OutputSize 8

    Write-HvResult "HvCallGetNextCpuGroupPartition" 0x00BB $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAddPhysicalMemory {
    <# .SYNOPSIS HvCallAddPhysicalMemory (0x00BC). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAddPhysicalMemory -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallAddPhysicalMemory" 0x00BC $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCompleteIntercept {
    <# .SYNOPSIS HvCallCompleteIntercept (0x00BD). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCompleteIntercept -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Pad                  = [uint32]0
    })

    Write-HvResult "HvCallCompleteIntercept" 0x00BD $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPrecommitGpaPages {
    <# .SYNOPSIS HvCallPrecommitGpaPages (0x00BE). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPrecommitGpaPages -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        GpaBase              = [uint64]0
        PageCount            = [uint64]0
    })

    Write-HvResult "HvCallPrecommitGpaPages" 0x00BE $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUncommitGpaPages {
    <# .SYNOPSIS HvCallUncommitGpaPages (0x00BF). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUncommitGpaPages -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        GpaBase              = [uint64]0
        PageCount            = [uint64]0
    })

    Write-HvResult "HvCallUncommitGpaPages" 0x00BF $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Direct messaging / dispatch / IOMMU / device domain V2 / VTL range /
#       sparse GPA host access / isolation / VP state / IPT / SNP /
#       extended partition property / extended hypercalls (0x00C0 - 0x8006)
# ==============================================================================

function Example-HvCallSignalEventDirect {
    <# .SYNOPSIS HvCallSignalEventDirect (0x00C0). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSignalEventDirect -InputData ([ordered]@{
        TargetPartition      = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Vtl                  = [byte]0
        Pad1                 = [byte]0
        Pad2                 = [uint16]0
        EventFlag            = [uint32]0
        Pad3                 = [uint32]0
    })

    Write-HvResult "HvCallSignalEventDirect" 0x00C0 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPostMessageDirect {
    <# .SYNOPSIS HvCallPostMessageDirect (0x00C1). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPostMessageDirect -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Vtl                  = [byte]0
        Pad1                 = [byte]0
        Pad2                 = [uint16]0
        SintIndex            = [uint32]0
        Pad3                 = [uint32]0
        Message0             = [uint64]0
        Message1             = [uint64]0
    })

    Write-HvResult "HvCallPostMessageDirect" 0x00C1 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDispatchVp {
    <# .SYNOPSIS HvCallDispatchVp (0x00C2). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDispatchVp -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Pad                  = [uint32]0
        TimeSlice            = [uint64]0
    })

    Write-HvResult "HvCallDispatchVp" 0x00C2 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallProcessIommuPrq {
    <# .SYNOPSIS HvCallProcessIommuPrq (0x00C3). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallProcessIommuPrq -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallProcessIommuPrq" 0x00C3 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDetachDeviceDomain {
    <# .SYNOPSIS HvCallDetachDeviceDomain (0x00C4). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDetachDeviceDomain -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallDetachDeviceDomain" 0x00C4 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeleteDeviceDomain {
    <# .SYNOPSIS HvCallDeleteDeviceDomain (0x00C5). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeleteDeviceDomain -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallDeleteDeviceDomain" 0x00C5 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallQueryDeviceDomain {
    <# .SYNOPSIS HvCallQueryDeviceDomain (0x00C6). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallQueryDeviceDomain -InputData ([byte[]]::new(16)) -OutputSize 16

    Write-HvResult "HvCallQueryDeviceDomain" 0x00C6 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallMapSparseDeviceGpaPages {
    <# .SYNOPSIS HvCallMapSparseDeviceGpaPages (0x00C7). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapSparseDeviceGpaPages -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallMapSparseDeviceGpaPages" 0x00C7 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnmapSparseDeviceGpaPages {
    <# .SYNOPSIS HvCallUnmapSparseDeviceGpaPages (0x00C8). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnmapSparseDeviceGpaPages -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallUnmapSparseDeviceGpaPages" 0x00C8 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetGpaPagesAccessState {
    <# .SYNOPSIS HvCallGetGpaPagesAccessState (0x00C9). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetGpaPagesAccessState -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        Flags                = [uint64]0
        GpaBase              = [uint64]0
    }) -OutputSize 4096

    Write-HvResult "HvCallGetGpaPagesAccessState" 0x00C9 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetSparseGpaPagesAccessState {
    <# .SYNOPSIS HvCallGetSparseGpaPagesAccessState (0x00CA). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetSparseGpaPagesAccessState -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 }) -OutputSize 4096

    Write-HvResult "HvCallGetSparseGpaPagesAccessState" 0x00CA $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallInvokeTestFramework {
    <# .SYNOPSIS HvCallInvokeTestFramework (0x00CB). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallInvokeTestFramework -InputData ([byte[]]::new(16)) -OutputSize 4096

    Write-HvResult "HvCallInvokeTestFramework" 0x00CB $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallQueryVtlProtectionMaskRange {
    <# .SYNOPSIS HvCallQueryVtlProtectionMaskRange (0x00CC). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallQueryVtlProtectionMaskRange -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        MapFlags             = [uint32]0
        TargetVtl            = [uint32]0
        GpaBase              = [uint64]0
        GpaCount             = [uint64]1
    }) -OutputSize 4096

    Write-HvResult "HvCallQueryVtlProtectionMaskRange" 0x00CC $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallModifyVtlProtectionMaskRange {
    <# .SYNOPSIS HvCallModifyVtlProtectionMaskRange (0x00CD). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallModifyVtlProtectionMaskRange -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        MapFlags             = [uint32]0x07
        TargetVtl            = [uint32]0
        GpaBase              = [uint64]0
        GpaCount             = [uint64]0
    })

    Write-HvResult "HvCallModifyVtlProtectionMaskRange" 0x00CD $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallConfigureDeviceDomain {
    <# .SYNOPSIS HvCallConfigureDeviceDomain (0x00CE). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallConfigureDeviceDomain -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallConfigureDeviceDomain" 0x00CE $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallQueryDeviceDomainProperties {
    <# .SYNOPSIS HvCallQueryDeviceDomainProperties (0x00CF). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallQueryDeviceDomainProperties -InputData ([byte[]]::new(8)) -OutputSize 32

    Write-HvResult "HvCallQueryDeviceDomainProperties" 0x00CF $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushDeviceDomain {
    <# .SYNOPSIS HvCallFlushDeviceDomain (0x00D0). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushDeviceDomain -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallFlushDeviceDomain" 0x00D0 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushDeviceDomainList {
    <# .SYNOPSIS HvCallFlushDeviceDomainList (0x00D1). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushDeviceDomainList -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallFlushDeviceDomainList" 0x00D1 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAcquireSparseGpaPageHostAccess {
    <# .SYNOPSIS HvCallAcquireSparseGpaPageHostAccess (0x00D2). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAcquireSparseGpaPageHostAccess -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallAcquireSparseGpaPageHostAccess" 0x00D2 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallReleaseSparseGpaPageHostAccess {
    <# .SYNOPSIS HvCallReleaseSparseGpaPageHostAccess (0x00D3). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallReleaseSparseGpaPageHostAccess -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallReleaseSparseGpaPageHostAccess" 0x00D3 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCheckSparseGpaPageVtlAccess {
    <# .SYNOPSIS HvCallCheckSparseGpaPageVtlAccess (0x00D4). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCheckSparseGpaPageVtlAccess -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        TargetVtl            = [uint32]0
        Pad                  = [uint32]0
    })

    Write-HvResult "HvCallCheckSparseGpaPageVtlAccess" 0x00D4 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallEnableDeviceInterrupt {
    <# .SYNOPSIS HvCallEnableDeviceInterrupt (0x00D5). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallEnableDeviceInterrupt -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallEnableDeviceInterrupt" 0x00D5 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallFlushTlb {
    <# .SYNOPSIS HvCallFlushTlb (0x00D6). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallFlushTlb -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallFlushTlb" 0x00D6 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAcquireSparseSpaPageHostAccess {
    <# .SYNOPSIS HvCallAcquireSparseSpaPageHostAccess (0x00D7). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAcquireSparseSpaPageHostAccess -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallAcquireSparseSpaPageHostAccess" 0x00D7 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallReleaseSparseSpaPageHostAccess {
    <# .SYNOPSIS HvCallReleaseSparseSpaPageHostAccess (0x00D8). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallReleaseSparseSpaPageHostAccess -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallReleaseSparseSpaPageHostAccess" 0x00D8 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallAcceptGpaPages {
    <# .SYNOPSIS HvCallAcceptGpaPages (0x00D9). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallAcceptGpaPages -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallAcceptGpaPages" 0x00D9 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnacceptGpaPages {
    <# .SYNOPSIS HvCallUnacceptGpaPages (0x00DA). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnacceptGpaPages -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallUnacceptGpaPages" 0x00DA $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallModifySparseGpaPageHostVisibility {
    <# .SYNOPSIS HvCallModifySparseGpaPageHostVisibility (0x00DB). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallModifySparseGpaPageHostVisibility -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallModifySparseGpaPageHostVisibility" 0x00DB $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallLockSparseGpaPageMapping {
    <# .SYNOPSIS HvCallLockSparseGpaPageMapping (0x00DC). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallLockSparseGpaPageMapping -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallLockSparseGpaPageMapping" 0x00DC $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnlockSparseGpaPageMapping {
    <# .SYNOPSIS HvCallUnlockSparseGpaPageMapping (0x00DD). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnlockSparseGpaPageMapping -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallUnlockSparseGpaPageMapping" 0x00DD $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRequestProcessorHalt {
    <# .SYNOPSIS HvCallRequestProcessorHalt (0x00DE). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRequestProcessorHalt -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallRequestProcessorHalt" 0x00DE $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetInterceptData {
    <# .SYNOPSIS HvCallGetInterceptData (0x00DF). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetInterceptData -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Pad                  = [uint32]0
    }) -OutputSize 4096

    Write-HvResult "HvCallGetInterceptData" 0x00DF $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallQueryDeviceInterruptTarget {
    <# .SYNOPSIS HvCallQueryDeviceInterruptTarget (0x00E0). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallQueryDeviceInterruptTarget -InputData ([byte[]]::new(24)) -OutputSize 32

    Write-HvResult "HvCallQueryDeviceInterruptTarget" 0x00E0 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallMapVpStatePage {
    <# .SYNOPSIS HvCallMapVpStatePage (0x00E1). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallMapVpStatePage -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Type                 = [uint32]0
    }) -OutputSize 8

    Write-HvResult "HvCallMapVpStatePage" 0x00E1 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnmapVpStatePage {
    <# .SYNOPSIS HvCallUnmapVpStatePage (0x00E2). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnmapVpStatePage -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Type                 = [uint32]0
    })

    Write-HvResult "HvCallUnmapVpStatePage" 0x00E2 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetVpState {
    <# .SYNOPSIS HvCallGetVpState (0x00E3). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetVpState -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Type                 = [uint32]0
    }) -OutputSize 4096

    Write-HvResult "HvCallGetVpState" 0x00E3 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetVpState {
    <# .SYNOPSIS HvCallSetVpState (0x00E4). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetVpState -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Type                 = [uint32]0
    })

    Write-HvResult "HvCallSetVpState" 0x00E4 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetVpSetFromMda {
    <# .SYNOPSIS HvCallGetVpSetFromMda (0x00E5). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetVpSetFromMda -InputData ([byte[]]::new(16)) -OutputSize 64

    Write-HvResult "HvCallGetVpSetFromMda" 0x00E5 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCreateIptBuffers {
    <# .SYNOPSIS HvCallCreateIptBuffers (0x00E7). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCreateIptBuffers -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallCreateIptBuffers" 0x00E7 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDeleteIptBuffers {
    <# .SYNOPSIS HvCallDeleteIptBuffers (0x00E8). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDeleteIptBuffers -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallDeleteIptBuffers" 0x00E8 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallControlHypervisorIptTrace {
    <# .SYNOPSIS HvCallControlHypervisorIptTrace (0x00E9). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallControlHypervisorIptTrace -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallControlHypervisorIptTrace" 0x00E9 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallReserveDeviceInterrupt {
    <# .SYNOPSIS HvCallReserveDeviceInterrupt (0x00EA). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallReserveDeviceInterrupt -InputData ([byte[]]::new(16)) -OutputSize 8

    Write-HvResult "HvCallReserveDeviceInterrupt" 0x00EA $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPersistDevice {
    <# .SYNOPSIS HvCallPersistDevice (0x00EB). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPersistDevice -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallPersistDevice" 0x00EB $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallUnpersistDevice {
    <# .SYNOPSIS HvCallUnpersistDevice (0x00EC). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallUnpersistDevice -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallUnpersistDevice" 0x00EC $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallPersistDeviceInterrupt {
    <# .SYNOPSIS HvCallPersistDeviceInterrupt (0x00ED). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallPersistDeviceInterrupt -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallPersistDeviceInterrupt" 0x00ED $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRefreshPerformanceCounters {
    <# .SYNOPSIS HvCallRefreshPerformanceCounters (0x00EE). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRefreshPerformanceCounters

    Write-HvResult "HvCallRefreshPerformanceCounters" 0x00EE $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallImportIsolatedPages {
    <# .SYNOPSIS HvCallImportIsolatedPages (0x00EF). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallImportIsolatedPages -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId; Flags=[uint64]0 })

    Write-HvResult "HvCallImportIsolatedPages" 0x00EF $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCompletePendingIsolatedPagesImport {
    <# .SYNOPSIS HvCallCompletePendingIsolatedPagesImport (0x00F0). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCompletePendingIsolatedPagesImport -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId })

    Write-HvResult "HvCallCompletePendingIsolatedPagesImport" 0x00F0 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCompleteIsolatedImport {
    <# .SYNOPSIS HvCallCompleteIsolatedImport (0x00F1). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCompleteIsolatedImport -InputData ([ordered]@{ PartitionId=[uint64]$ctx.PartitionId })

    Write-HvResult "HvCallCompleteIsolatedImport" 0x00F1 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallIssueSnpPspGuestRequest {
    <# .SYNOPSIS HvCallIssueSnpPspGuestRequest (0x00F2). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallIssueSnpPspGuestRequest -InputData ([byte[]]::new(32)) -OutputSize 32

    Write-HvResult "HvCallIssueSnpPspGuestRequest" 0x00F2 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRootSignalEvent {
    <# .SYNOPSIS HvCallRootSignalEvent (0x00F3). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRootSignalEvent -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallRootSignalEvent" 0x00F3 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallGetVpCpuidValues {
    <# .SYNOPSIS HvCallGetVpCpuidValues (0x00F4). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetVpCpuidValues -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        VpIndex              = [uint32]0
        Pad                  = [uint32]0
    }) -OutputSize 4096

    Write-HvResult "HvCallGetVpCpuidValues" 0x00F4 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallReadSystemMemory {
    <# .SYNOPSIS HvCallReadSystemMemory (0x00F5). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallReadSystemMemory -InputData ([byte[]]::new(16)) -OutputSize 4096

    Write-HvResult "HvCallReadSystemMemory" 0x00F5 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSetHwWatchdogConfig {
    <# .SYNOPSIS HvCallSetHwWatchdogConfig (0x00F6). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSetHwWatchdogConfig -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallSetHwWatchdogConfig" 0x00F6 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallRemovePhysicalMemory {
    <# .SYNOPSIS HvCallRemovePhysicalMemory (0x00F7). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallRemovePhysicalMemory -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallRemovePhysicalMemory" 0x00F7 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallLogHypervisorSystemConfig {
    <# .SYNOPSIS HvCallLogHypervisorSystemConfig (0x00F8). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallLogHypervisorSystemConfig -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallLogHypervisorSystemConfig" 0x00F8 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallIssueNestedSnpPspRequests {
    <# .SYNOPSIS HvCallIssueNestedSnpPspRequests (0x00F9). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallIssueNestedSnpPspRequests -InputData ([byte[]]::new(32))

    Write-HvResult "HvCallIssueNestedSnpPspRequests" 0x00F9 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallCompleteSnpPspRequests {
    <# .SYNOPSIS HvCallCompleteSnpPspRequests (0x00FA). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallCompleteSnpPspRequests -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallCompleteSnpPspRequests" 0x00FA $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSubsumeInitializedMemory {
    <# .SYNOPSIS HvCallSubsumeInitializedMemory (0x00FB). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSubsumeInitializedMemory -InputData ([byte[]]::new(24))

    Write-HvResult "HvCallSubsumeInitializedMemory" 0x00FB $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallSubsumeVp {
    <# .SYNOPSIS HvCallSubsumeVp (0x00FC). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallSubsumeVp -InputData ([byte[]]::new(16))

    Write-HvResult "HvCallSubsumeVp" 0x00FC $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvCallDestroySubsumedContext {
    <# .SYNOPSIS HvCallDestroySubsumedContext (0x00FD). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallDestroySubsumedContext -InputData ([byte[]]::new(8))

    Write-HvResult "HvCallDestroySubsumedContext" 0x00FD $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

# 0x0101

function Example-HvCallGetPartitionPropertyEx {
    <# .SYNOPSIS HvCallGetPartitionPropertyEx (0x0101). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvCallGetPartitionPropertyEx -InputData ([ordered]@{
        PartitionId          = [uint64]$ctx.PartitionId
        PropertyCode         = [uint32]0
        Pad                  = [uint32]0
    }) -OutputSize 16

    Write-HvResult "HvCallGetPartitionPropertyEx" 0x0101 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

# Extended hypercalls (0x8001 - 0x8006)

function Example-HvExtCallQueryCapabilities {
    <# .SYNOPSIS HvExtCallQueryCapabilities (0x8001). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvExtCallQueryCapabilities -OutputSize 8

    Write-HvResult "HvExtCallQueryCapabilities" 0x8001 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvExtCallGetBootZeroedMemory {
    <# .SYNOPSIS HvExtCallGetBootZeroedMemory (0x8002). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvExtCallGetBootZeroedMemory -OutputSize 16

    Write-HvResult "HvExtCallGetBootZeroedMemory" 0x8002 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvExtCallMemoryHeatHint {
    <# .SYNOPSIS HvExtCallMemoryHeatHint (0x8003). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvExtCallMemoryHeatHint -InputData ([byte[]]::new(16))

    Write-HvResult "HvExtCallMemoryHeatHint" 0x8003 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvExtCallEpfSetup {
    <# .SYNOPSIS HvExtCallEpfSetup (0x8004). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvExtCallEpfSetup -InputData ([byte[]]::new(16))

    Write-HvResult "HvExtCallEpfSetup" 0x8004 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvExtCallSchedulerAssistSetup {
    <# .SYNOPSIS HvExtCallSchedulerAssistSetup (0x8005). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvExtCallSchedulerAssistSetup -InputData ([byte[]]::new(16))

    Write-HvResult "HvExtCallSchedulerAssistSetup" 0x8005 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

function Example-HvExtCallMemoryHeatHintAsync {
    <# .SYNOPSIS HvExtCallMemoryHeatHintAsync (0x8006). #>
    param([string]$VmName = $script:VmName)
    $ctx = Open-TestPartition $VmName
    if (-not $ctx) { return }

    $r = Invoke-HypercallRaw -CallCode $HvCallCode.HvExtCallMemoryHeatHintAsync -InputData ([byte[]]::new(16))

    Write-HvResult "HvExtCallMemoryHeatHintAsync" 0x8006 $r.Ok
    Close-HvlibPartition -handle $ctx.Handle
    return $r
}

#endregion


# ==============================================================================
#region Invoke-AllHvExamples — run every example and print summary
# ==============================================================================

function Invoke-AllHvExamples {
    <#
    .SYNOPSIS
    Run all hypercall examples and print summary table.
    .EXAMPLE
    . .\Hvlib-HvExamples.ps1
    Invoke-AllHvExamples -VmName "Windows Server 2025"
    #>
    param(
        [string]$VmName = $script:VmName,
        [string]$DllPath = $script:DllPath
    )

    Write-Host "`n$('=' * 80)" -ForegroundColor Magenta
    Write-Host "Hvlib Hypercall Examples — Complete Table" -ForegroundColor Magenta
    Write-Host "$('=' * 80)`n" -ForegroundColor Magenta

    # Initialize Hvlib: load DLL via Get-Hvlib (required before any partition operations)
    if (Test-Path $DllPath) {
        $initResult = Get-Hvlib -path_to_dll $DllPath
        if (-not $initResult) {
            Write-Warning "Get-Hvlib failed for: $DllPath"
            return
        }
        Write-Host ("  DLL loaded: {0}" -f $DllPath) -ForegroundColor Green
    } else {
        Write-Warning "DLL not found: $DllPath"
        return
    }

    # Collect all Example-HvCall* and Example-HvExtCall* functions
    $fns = Get-Command -Name "Example-HvCall*", "Example-HvExtCall*" -CommandType Function |
        Sort-Object Name

    Write-Host ("  Total example functions: {0}`n" -f $fns.Count) -ForegroundColor Cyan

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($fn in $fns) {
        try {
            $r = & $fn.Name -VmName $VmName
            $ok = if ($null -eq $r) { $false }
                  elseif ($r -is [hashtable] -and $null -ne $r['Ok']) { $r.Ok }
                  elseif ($r.PSObject.Properties['Ok']) { $r.Ok }
                  elseif ($r.PSObject.Properties['ReadOk']) { $r.ReadOk }
                  else { $false }
        } catch {
            $ok = $false
            Write-Host ("  [EXCEPTION] {0}: {1}" -f $fn.Name, $_.Exception.Message) -ForegroundColor Red
        }
        $results.Add([PSCustomObject]@{ Name = $fn.Name; Ok = $ok })
    }

    # Summary
    $okCount   = ($results | Where-Object Ok).Count
    $failCount = ($results | Where-Object { -not $_.Ok }).Count

    Write-Host "`n$('=' * 80)" -ForegroundColor Magenta
    Write-Host ("  Total: {0}   HV_STATUS_SUCCESS: {1}   FAILED: {2}" -f $results.Count, $okCount, $failCount) -ForegroundColor Cyan
    Write-Host "$('=' * 80)" -ForegroundColor Magenta

    if ($okCount -gt 0) {
        Write-Host "`n  Successful:" -ForegroundColor Green
        $results | Where-Object Ok | ForEach-Object { Write-Host ("    {0}" -f $_.Name) -ForegroundColor Green }
    }

    return $results
}

#endregion


# --- Auto-run ---
Invoke-AllHvExamples -DllPath $script:DllPath -VmName $script:VmName

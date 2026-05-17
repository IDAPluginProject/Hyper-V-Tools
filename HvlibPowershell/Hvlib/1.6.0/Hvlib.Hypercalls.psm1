# ==============================================================================
# Module:      Hvlib.Hypercalls.psm1
# Version:     1.0.0
# Description: Typed Hyper-V hypercall wrappers based on TLFS (Top Level
#              Functional Specification) and generic hypercall invocation.
# Author:      Arthur Khudyaev (www.x.com/gerhart_x)
# ==============================================================================
#
# References:
#   [TLFS] Microsoft Hypervisor Top Level Functional Specification
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
#
#   [TLFS-Hypercalls] Hypercall interface
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
#
#   [TLFS-MemoryAccess] HvCallReadGpa / HvCallWriteGpa
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallReadGpa
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallWriteGpa
#
#   [TLFS-VpRegisters] HvCallGetVpRegisters / HvCallSetVpRegisters
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetVpRegisters
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSetVpRegisters
#
#   [TLFS-VA] HvCallTranslateVirtualAddress
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallTranslateVirtualAddress
#
#   [TLFS-SynIC] HvCallPostMessage / HvCallSignalEvent
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallPostMessage
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSignalEvent
#
#   [TLFS-PartitionId] HvCallGetPartitionId
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetPartitionId
#
#   [TLFS-Appendix] Register names, hypercall codes, status codes
#          https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv-register-name
#
#   [hvlib SDK] LiveCloudKd / hvlib — SdkInvokeHypercall
#          https://github.com/gerhart01/LiveCloudKd
#
# Architecture:
#   PowerShell (this module)         C# (hvlibdotnet.dll)         Driver (hvmm.sys)
#   +--------------------------+     +---------------------+      +------------------+
#   | Invoke-HvCallReadGpa     |     | InvokeHypercallBytes|      | SdkInvokeHypercall|
#   | Invoke-HvCallWriteGpa    | --> |  byte[] -> byte[]   | -->  | AllocPages,vmcall |
#   | Invoke-HypercallRaw         |     |  (buffer mgmt)      |      |  (kernel mode)    |
#   +--------------------------+     +---------------------+      +------------------+
#
# Change Log:
# 1.0.0 - Initial release
#       - Invoke-HypercallRaw          — generic: any hypercall via code + byte[]/ordered/array
#       - Invoke-HvCallReadGpa      — 0x0053: read up to 16 bytes from GPA
#       - Invoke-HvCallWriteGpa     — 0x0054: write up to 16 bytes to GPA
#       - Invoke-HvCallGetPartitionId — 0x0046: get calling partition ID
#       - Invoke-HvCallGetVpRegisters — 0x0050: read VP registers (rep)
#       - Invoke-HvCallSetVpRegisters — 0x0051: write VP registers (rep)
#       - Invoke-HvCallTranslateVirtualAddress — 0x0052: GVA → GPA translation
#       - Invoke-HvCallPostMessage  — 0x005C: post SynIC message
#       - Invoke-HvCallSignalEvent  — 0x005D: signal SynIC event
#       - Total: 9 public functions
# ==============================================================================


# ==============================================================================
#region Hypercall code constants
# ==============================================================================

# Hypercall codes — complete table from hvgdk.h, hvgdk_mini.h, and TLFS.
# Key naming follows hvgdk.h convention: HvCall<Name>
#
# Sources:
#   [hvgdk.h]      LiveCloudKd SDK / ionescu007/hdk
#   [hvgdk_mini.h] Linux kernel / mshv headers
#   [mu_msvm]      microsoft/mu_msvm HvGuestHypercall.h
#   [TLFS]         Microsoft Hypervisor Top Level Functional Specification
#   [RE]           Reverse-engineered from hv.exe / hvix64.exe (Win11+)
#
# https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface

$Script:HvCallCode = [ordered]@{

    # ── V1 core / fast hypercalls (0x0000 – 0x0007) ──────────────────────────

    HvCallReserved0000                      = [uint16]0x0000
    HvCallSwitchVirtualAddressSpace         = [uint16]0x0001
    HvCallFlushVirtualAddressSpace          = [uint16]0x0002
    HvCallFlushVirtualAddressList           = [uint16]0x0003
    HvCallGetLogicalProcessorRunTime        = [uint16]0x0004
    HvCallUpdateHvProcessorFeatures         = [uint16]0x0005   # hvgdk.h: SetLogicalProcessorRunTimeGroup
    HvCallSwitchAliasMap                    = [uint16]0x0006   # hvgdk.h: ClearLogicalProcessorRunTimeGroup
    HvCallUpdateMicrocode                   = [uint16]0x0007   # hvgdk.h: NotifyLogicalProcessorPowerState

    # ── VTL / IPI / flush-ex / patching (0x0008 – 0x001F) ────────────────────

    HvCallNotifyLongSpinWait                = [uint16]0x0008
    HvCallParkedVirtualProcessors           = [uint16]0x0009
    HvCallInvokeHypervisorDebugger          = [uint16]0x000A
    HvCallSendSyntheticClusterIpi           = [uint16]0x000B
    HvCallModifyVtlProtectionMask           = [uint16]0x000C
    HvCallEnablePartitionVtl                = [uint16]0x000D
    HvCallDisablePartitionVtl               = [uint16]0x000E
    HvCallEnableVpVtl                       = [uint16]0x000F
    HvCallDisableVpVtl                      = [uint16]0x0010
    HvCallVtlCall                           = [uint16]0x0011
    HvCallVtlReturn                         = [uint16]0x0012
    HvCallFlushVirtualAddressSpaceEx        = [uint16]0x0013
    HvCallFlushVirtualAddressListEx         = [uint16]0x0014
    HvCallSendSyntheticClusterIpiEx         = [uint16]0x0015
    HvCallQueryImageInfo                    = [uint16]0x0016
    HvCallMapImagePages                     = [uint16]0x0017
    HvCallCommitPatch                       = [uint16]0x0018
    HvCallSyncContext                       = [uint16]0x0019
    HvCallSyncContextEx                     = [uint16]0x001A
    HvCallSetPerfRegister                   = [uint16]0x001B
    HvCallGetPerfRegister                   = [uint16]0x001C
    HvCallReserved001d                      = [uint16]0x001D
    HvCallReserved001e                      = [uint16]0x001E
    HvCallReserved001f                      = [uint16]0x001F

    # ── Reserved block (0x0020 – 0x003F) ─────────────────────────────────────

    HvCallReserved0020                      = [uint16]0x0020
    HvCallReserved0021                      = [uint16]0x0021
    HvCallReserved0022                      = [uint16]0x0022
    HvCallReserved0023                      = [uint16]0x0023
    HvCallReserved0024                      = [uint16]0x0024
    HvCallReserved0025                      = [uint16]0x0025
    HvCallReserved0026                      = [uint16]0x0026
    HvCallReserved0027                      = [uint16]0x0027
    HvCallReserved0028                      = [uint16]0x0028
    HvCallReserved0029                      = [uint16]0x0029
    HvCallReserved002a                      = [uint16]0x002A
    HvCallReserved002b                      = [uint16]0x002B
    HvCallReserved002c                      = [uint16]0x002C
    HvCallReserved002d                      = [uint16]0x002D
    HvCallReserved002e                      = [uint16]0x002E
    HvCallReserved002f                      = [uint16]0x002F
    HvCallReserved0030                      = [uint16]0x0030
    HvCallReserved0031                      = [uint16]0x0031
    HvCallReserved0032                      = [uint16]0x0032
    HvCallReserved0033                      = [uint16]0x0033
    HvCallReserved0034                      = [uint16]0x0034
    HvCallReserved0035                      = [uint16]0x0035
    HvCallReserved0036                      = [uint16]0x0036
    HvCallReserved0037                      = [uint16]0x0037
    HvCallReserved0038                      = [uint16]0x0038
    HvCallReserved0039                      = [uint16]0x0039
    HvCallReserved003a                      = [uint16]0x003A
    HvCallReserved003b                      = [uint16]0x003B
    HvCallReserved003c                      = [uint16]0x003C
    HvCallReserved003d                      = [uint16]0x003D
    HvCallReserved003e                      = [uint16]0x003E
    HvCallReserved003f                      = [uint16]0x003F

    # ── Partition management (0x0040 – 0x0047) ───────────────────────────────

    HvCallCreatePartition                   = [uint16]0x0040
    HvCallInitializePartition               = [uint16]0x0041
    HvCallFinalizePartition                 = [uint16]0x0042
    HvCallDeletePartition                   = [uint16]0x0043
    HvCallGetPartitionProperty              = [uint16]0x0044
    HvCallSetPartitionProperty              = [uint16]0x0045
    HvCallGetPartitionId                    = [uint16]0x0046
    HvCallGetNextChildPartition             = [uint16]0x0047

    # ── Memory management (0x0048 – 0x004A) ──────────────────────────────────

    HvCallDepositMemory                     = [uint16]0x0048
    HvCallWithdrawMemory                    = [uint16]0x0049
    HvCallGetMemoryBalance                  = [uint16]0x004A

    # ── GPA management (0x004B – 0x004C) ─────────────────────────────────────

    HvCallMapGpaPages                       = [uint16]0x004B
    HvCallUnmapGpaPages                     = [uint16]0x004C

    # ── Intercept (0x004D) ───────────────────────────────────────────────────

    HvCallInstallIntercept                  = [uint16]0x004D

    # ── Virtual processor (0x004E – 0x0051) ──────────────────────────────────

    HvCallCreateVp                          = [uint16]0x004E
    HvCallDeleteVp                          = [uint16]0x004F
    HvCallGetVpRegisters                    = [uint16]0x0050
    HvCallSetVpRegisters                    = [uint16]0x0051

    # ── Virtual TLB / GPA read-write (0x0052 – 0x0054) ───────────────────────

    HvCallTranslateVirtualAddress           = [uint16]0x0052
    HvCallReadGpa                           = [uint16]0x0053
    HvCallWriteGpa                          = [uint16]0x0054

    # ── Interrupts (0x0055 – 0x0056) ─────────────────────────────────────────

    HvCallAssertVirtualInterruptDeprecated  = [uint16]0x0055
    HvCallClearVirtualInterrupt             = [uint16]0x0056

    # ── Ports / messaging (0x0057 – 0x005D) ──────────────────────────────────

    HvCallCreatePortDeprecated              = [uint16]0x0057
    HvCallDeletePort                        = [uint16]0x0058
    HvCallConnectPortDeprecated             = [uint16]0x0059
    HvCallGetPortProperty                   = [uint16]0x005A
    HvCallDisconnectPort                    = [uint16]0x005B
    HvCallPostMessage                       = [uint16]0x005C
    HvCallSignalEvent                       = [uint16]0x005D

    # ── Partition state (0x005E – 0x005F) ────────────────────────────────────

    HvCallSavePartitionState                = [uint16]0x005E
    HvCallRestorePartitionState             = [uint16]0x005F

    # ── Event logging (0x0060 – 0x0068) ──────────────────────────────────────

    HvCallInitializeEventLogBufferGroup     = [uint16]0x0060
    HvCallFinalizeEventLogBufferGroup       = [uint16]0x0061
    HvCallCreateEventLogBuffer              = [uint16]0x0062
    HvCallDeleteEventLogBuffer              = [uint16]0x0063
    HvCallMapEventLogBuffer                 = [uint16]0x0064
    HvCallUnmapEventLogBuffer               = [uint16]0x0065
    HvCallSetEventLogGroupSources           = [uint16]0x0066
    HvCallReleaseEventLogBuffer             = [uint16]0x0067
    HvCallFlushEventLogBuffer               = [uint16]0x0068

    # ── Debugging (0x0069 – 0x006B) ──────────────────────────────────────────

    HvCallPostDebugData                     = [uint16]0x0069
    HvCallRetrieveDebugData                 = [uint16]0x006A
    HvCallResetDebugSession                 = [uint16]0x006B

    # ── Statistics (0x006C – 0x006D) ─────────────────────────────────────────

    HvCallMapStatsPage                      = [uint16]0x006C
    HvCallUnmapStatsPage                    = [uint16]0x006D

    # ── V1 extended / test (0x006E – 0x0075) ─────────────────────────────────

    HvCallMapSparseGpaPages                 = [uint16]0x006E
    HvCallSetSystemProperty                 = [uint16]0x006F
    HvCallSetPortProperty                   = [uint16]0x0070
    HvCallOutputDebugCharacter              = [uint16]0x0071
    HvCallEchoIncrement                     = [uint16]0x0072
    HvCallPerfNop                           = [uint16]0x0073
    HvCallPerfNopInput                      = [uint16]0x0074
    HvCallPerfNopOutput                     = [uint16]0x0075

    # ── V2 logical processor / NUMA (0x0076 – 0x007B) ────────────────────────

    HvCallAddLogicalProcessor               = [uint16]0x0076
    HvCallRemoveLogicalProcessor            = [uint16]0x0077
    HvCallQueryNumaDistance                  = [uint16]0x0078
    HvCallSetLogicalProcessorProperty       = [uint16]0x0079
    HvCallGetLogicalProcessorProperty       = [uint16]0x007A
    HvCallGetSystemProperty                 = [uint16]0x007B

    # ── Device interrupts (0x007C – 0x0080) ──────────────────────────────────

    HvCallMapDeviceInterrupt                = [uint16]0x007C
    HvCallUnmapDeviceInterrupt              = [uint16]0x007D
    HvCallRetargetDeviceInterrupt           = [uint16]0x007E
    HvCallRetargetRootDeviceInterrupt       = [uint16]0x007F
    HvCallAssertDeviceInterrupt             = [uint16]0x0080

    # ── Device attach / power / MCA (0x0081 – 0x008F) ────────────────────────

    HvCallReserved0081                      = [uint16]0x0081
    HvCallAttachDevice                      = [uint16]0x0082
    HvCallDetachDevice                      = [uint16]0x0083
    HvCallEnterSleepState                   = [uint16]0x0084
    HvCallNotifyStandbyTransition           = [uint16]0x0085
    HvCallPrepareForHibernate               = [uint16]0x0086
    HvCallNotifyPartitionEvent              = [uint16]0x0087
    HvCallGetLogicalProcessorRegisters      = [uint16]0x0088
    HvCallSetLogicalProcessorRegisters      = [uint16]0x0089
    HvCallQueryAssociatedLpsForMca          = [uint16]0x008A
    HvCallNotifyPortRingEmpty               = [uint16]0x008B
    HvCallInjectSyntheticMachineCheck       = [uint16]0x008C
    HvCallScrubPartition                    = [uint16]0x008D
    HvCallCollectLivedump                   = [uint16]0x008E
    HvCallDisableHypervisor                 = [uint16]0x008F

    # ── Sparse GPA / intercept result / assert (0x0090 – 0x009C) ─────────────

    HvCallModifySparseGpaPages              = [uint16]0x0090
    HvCallRegisterInterceptResult           = [uint16]0x0091
    HvCallUnregisterInterceptResult         = [uint16]0x0092
    HvCallGetCoverageData                   = [uint16]0x0093
    HvCallAssertVirtualInterrupt            = [uint16]0x0094
    HvCallCreatePort                        = [uint16]0x0095
    HvCallConnectPort                       = [uint16]0x0096
    HvCallGetSpaPageList                    = [uint16]0x0097
    HvCallReserved0098                      = [uint16]0x0098
    HvCallStartVirtualProcessor             = [uint16]0x0099
    HvCallGetVpIndexFromApicId              = [uint16]0x009A
    HvCallGetPowerProperty                  = [uint16]0x009B
    HvCallSetPowerProperty                  = [uint16]0x009C

    # ── PASID (0x009D – 0x00A9) ──────────────────────────────────────────────

    HvCallCreatePasidSpace                  = [uint16]0x009D
    HvCallDeletePasidSpace                  = [uint16]0x009E
    HvCallSetPasidAddressSpace              = [uint16]0x009F
    HvCallFlushPasidAddressSpace            = [uint16]0x00A0
    HvCallFlushPasidAddressList             = [uint16]0x00A1
    HvCallAttachPasidSpace                  = [uint16]0x00A2
    HvCallDetachPasidSpace                  = [uint16]0x00A3
    HvCallEnablePasid                       = [uint16]0x00A4
    HvCallDisablePasid                      = [uint16]0x00A5
    HvCallAcknowledgeDevicePageRequest      = [uint16]0x00A6
    HvCallCreateDevicePrQueue               = [uint16]0x00A7
    HvCallDeleteDevicePrQueue               = [uint16]0x00A8
    HvCallSetDevicePrqProperty              = [uint16]0x00A9

    # ── Physical device / translate-ex / GPA attributes (0x00AA – 0x00B0) ────

    HvCallGetPhysicalDeviceProperty         = [uint16]0x00AA
    HvCallSetPhysicalDeviceProperty         = [uint16]0x00AB
    HvCallTranslateVirtualAddressEx         = [uint16]0x00AC
    HvCallCheckForIoIntercept               = [uint16]0x00AD
    HvCallSetGpaPageAttributes              = [uint16]0x00AE
    HvCallFlushGuestPhysicalAddressSpace    = [uint16]0x00AF
    HvCallFlushGuestPhysicalAddressList     = [uint16]0x00B0

    # ── Device domain (0x00B1 – 0x00B4) ──────────────────────────────────────

    HvCallCreateDeviceDomain                = [uint16]0x00B1
    HvCallAttachDeviceDomain                = [uint16]0x00B2
    HvCallMapDeviceGpaPages                 = [uint16]0x00B3
    HvCallUnmapDeviceGpaPages               = [uint16]0x00B4

    # ── CPU groups (0x00B5 – 0x00BB) ─────────────────────────────────────────

    HvCallCreateCpuGroup                    = [uint16]0x00B5
    HvCallDeleteCpuGroup                    = [uint16]0x00B6
    HvCallGetCpuGroupProperty               = [uint16]0x00B7
    HvCallSetCpuGroupProperty               = [uint16]0x00B8
    HvCallGetCpuGroupAffinity               = [uint16]0x00B9
    HvCallGetNextCpuGroup                   = [uint16]0x00BA
    HvCallGetNextCpuGroupPartition          = [uint16]0x00BB

    # ── Memory / intercept / GPA commit (0x00BC – 0x00BF) ────────────────────

    HvCallAddPhysicalMemory                 = [uint16]0x00BC
    HvCallCompleteIntercept                 = [uint16]0x00BD
    HvCallPrecommitGpaPages                 = [uint16]0x00BE
    HvCallUncommitGpaPages                  = [uint16]0x00BF

    # ── Direct messaging / dispatch / IOMMU (0x00C0 – 0x00CB) ────────────────

    HvCallSignalEventDirect                 = [uint16]0x00C0
    HvCallPostMessageDirect                 = [uint16]0x00C1
    HvCallDispatchVp                        = [uint16]0x00C2
    HvCallProcessIommuPrq                   = [uint16]0x00C3
    HvCallDetachDeviceDomain                = [uint16]0x00C4
    HvCallDeleteDeviceDomain                = [uint16]0x00C5
    HvCallQueryDeviceDomain                 = [uint16]0x00C6
    HvCallMapSparseDeviceGpaPages           = [uint16]0x00C7
    HvCallUnmapSparseDeviceGpaPages         = [uint16]0x00C8
    HvCallGetGpaPagesAccessState            = [uint16]0x00C9
    HvCallGetSparseGpaPagesAccessState      = [uint16]0x00CA
    HvCallInvokeTestFramework               = [uint16]0x00CB

    # ── VTL protection range / device domain config (0x00CC – 0x00D1) ────────

    HvCallQueryVtlProtectionMaskRange       = [uint16]0x00CC
    HvCallModifyVtlProtectionMaskRange      = [uint16]0x00CD
    HvCallConfigureDeviceDomain             = [uint16]0x00CE
    HvCallQueryDeviceDomainProperties       = [uint16]0x00CF
    HvCallFlushDeviceDomain                 = [uint16]0x00D0
    HvCallFlushDeviceDomainList             = [uint16]0x00D1

    # ── Sparse GPA host access / VTL check (0x00D2 – 0x00D8) ────────────────

    HvCallAcquireSparseGpaPageHostAccess    = [uint16]0x00D2
    HvCallReleaseSparseGpaPageHostAccess    = [uint16]0x00D3
    HvCallCheckSparseGpaPageVtlAccess       = [uint16]0x00D4
    HvCallEnableDeviceInterrupt             = [uint16]0x00D5
    HvCallFlushTlb                          = [uint16]0x00D6
    HvCallAcquireSparseSpaPageHostAccess    = [uint16]0x00D7
    HvCallReleaseSparseSpaPageHostAccess    = [uint16]0x00D8

    # ── Isolation / GPA accept (0x00D9 – 0x00DF) ────────────────────────────

    HvCallAcceptGpaPages                    = [uint16]0x00D9
    HvCallUnacceptGpaPages                  = [uint16]0x00DA
    HvCallModifySparseGpaPageHostVisibility = [uint16]0x00DB
    HvCallLockSparseGpaPageMapping          = [uint16]0x00DC
    HvCallUnlockSparseGpaPageMapping        = [uint16]0x00DD
    HvCallRequestProcessorHalt              = [uint16]0x00DE
    HvCallGetInterceptData                  = [uint16]0x00DF

    # ── VP state / IPT / persistence (0x00E0 – 0x00EE) ──────────────────────

    HvCallQueryDeviceInterruptTarget        = [uint16]0x00E0
    HvCallMapVpStatePage                    = [uint16]0x00E1
    HvCallUnmapVpStatePage                  = [uint16]0x00E2
    HvCallGetVpState                        = [uint16]0x00E3
    HvCallSetVpState                        = [uint16]0x00E4
    HvCallGetVpSetFromMda                   = [uint16]0x00E5
    HvCallReserved00e6                      = [uint16]0x00E6
    HvCallCreateIptBuffers                  = [uint16]0x00E7
    HvCallDeleteIptBuffers                  = [uint16]0x00E8
    HvCallControlHypervisorIptTrace         = [uint16]0x00E9
    HvCallReserveDeviceInterrupt            = [uint16]0x00EA
    HvCallPersistDevice                     = [uint16]0x00EB
    HvCallUnpersistDevice                   = [uint16]0x00EC
    HvCallPersistDeviceInterrupt            = [uint16]0x00ED
    HvCallRefreshPerformanceCounters        = [uint16]0x00EE

    # ── SNP / isolated import (0x00EF – 0x00FD) ─────────────────────────────

    HvCallImportIsolatedPages               = [uint16]0x00EF
    HvCallCompletePendingIsolatedPagesImport = [uint16]0x00F0
    HvCallCompleteIsolatedImport            = [uint16]0x00F1
    HvCallIssueSnpPspGuestRequest           = [uint16]0x00F2
    HvCallRootSignalEvent                   = [uint16]0x00F3
    HvCallGetVpCpuidValues                  = [uint16]0x00F4
    HvCallReadSystemMemory                  = [uint16]0x00F5
    HvCallSetHwWatchdogConfig               = [uint16]0x00F6
    HvCallRemovePhysicalMemory              = [uint16]0x00F7
    HvCallLogHypervisorSystemConfig         = [uint16]0x00F8
    HvCallIssueNestedSnpPspRequests         = [uint16]0x00F9
    HvCallCompleteSnpPspRequests            = [uint16]0x00FA
    HvCallSubsumeInitializedMemory          = [uint16]0x00FB
    HvCallSubsumeVp                         = [uint16]0x00FC
    HvCallDestroySubsumedContext            = [uint16]0x00FD

    # ── Extended partition property (0x0101) ─────────────────────────────────

    HvCallGetPartitionPropertyEx            = [uint16]0x0101

    # ── Extended hypercalls (0x8001 – 0x8006) ────────────────────────────────

    HvExtCallQueryCapabilities              = [uint16]0x8001
    HvExtCallGetBootZeroedMemory            = [uint16]0x8002
    HvExtCallMemoryHeatHint                 = [uint16]0x8003
    HvExtCallEpfSetup                       = [uint16]0x8004
    HvExtCallSchedulerAssistSetup           = [uint16]0x8005
    HvExtCallMemoryHeatHintAsync            = [uint16]0x8006
}

#endregion






# ==============================================================================
#region Internal helpers
# ==============================================================================

function ConvertTo-HypercallBytes {
    <#
    .SYNOPSIS
    Serialize a single typed value to its little-endian byte representation.
    .DESCRIPTION
    Internal helper for Invoke-HypercallRaw. Converts PowerShell typed values
    to byte arrays matching their C struct layout (little-endian).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Value)

    switch ($Value) {
        { $_ -is [byte] }   { return ,[byte[]]@($Value) }
        { $_ -is [uint16] } { return ,[BitConverter]::GetBytes([uint16]$Value) }
        { $_ -is [int16] }  { return ,[BitConverter]::GetBytes([int16]$Value) }
        { $_ -is [uint32] } { return ,[BitConverter]::GetBytes([uint32]$Value) }
        { $_ -is [int32] }  { return ,[BitConverter]::GetBytes([int32]$Value) }
        { $_ -is [uint64] } { return ,[BitConverter]::GetBytes([uint64]$Value) }
        { $_ -is [int64] }  { return ,[BitConverter]::GetBytes([int64]$Value) }
        { $_ -is [byte[]] } { return ,$Value }
        default { throw "Unsupported type [$($Value.GetType().Name)]" }
    }
}

#endregion


# ==============================================================================
#region Generic hypercall interface
# ==============================================================================

function Invoke-HypercallRaw {
    <#
    .SYNOPSIS
    Generic hypercall invocation with automatic serialization.
    .DESCRIPTION
    Universal entry point for ANY Hyper-V hypercall. Accepts input as:
      - [ordered]@{} hashtable  — field names + typed values, serialized in order
      - [object[]] array        — typed values serialized sequentially
      - [byte[]] raw bytes      — copied as-is

    All buffer management (AllocHGlobal/FreeHGlobal, copy in/out) is handled
    by the C# method [Hvlibdotnet.Hvlib]::InvokeHypercallBytes.

    For known hypercalls, prefer the typed wrappers (Invoke-HvCallReadGpa, etc.)
    which provide named parameters and parsed output.

    Type-to-size mapping for automatic serialization:
      [byte]   -> 1    [uint16]/[int16] -> 2    [uint32]/[int32] -> 4
      [uint64]/[int64] -> 8    [byte[]] -> length of array

    .PARAMETER CallCode
    Hypercall code (e.g. 0x0053 for HvCallReadGpa).
    See [TLFS] https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface

    .PARAMETER InputData
    Input data: [ordered]@{...}, typed array, or [byte[]].

    .PARAMETER OutputSize
    Expected output size in bytes (default 4096, max 4096).

    .PARAMETER IsFast
    Use fast hypercall (register-only, no input/output pages).

    .PARAMETER CountOfElements
    Rep count for rep hypercalls (e.g. number of registers for HvCallGetVpRegisters).

    .PARAMETER RepStartIndex
    Rep start index for rep hypercalls.

    .PARAMETER IsNested
    Nested hypercall flag.

    .EXAMPLE
    # HvCallReadGpa — read 16 bytes from GPA 0x1000, partition 3
    $r = Invoke-HypercallRaw -CallCode 0x0053 -InputData ([ordered]@{
        PartitionId  = [uint64]3
        VpIndex      = [uint32]0
        ByteCount    = [uint32]16
        BaseGpa      = [uint64]0x1000
        ControlFlags = [uint64]0
    }) -OutputSize 24

    .EXAMPLE
    # Same call, compact array form
    $r = Invoke-HypercallRaw 0x0053 -InputData ([uint64]3, [uint32]0, [uint32]16, [uint64]0x1000, [uint64]0) -OutputSize 24

    .EXAMPLE
    # Raw byte array form
    $bytes = [byte[]]::new(32)
    [BitConverter]::GetBytes([uint64]3).CopyTo($bytes, 0)
    $r = Invoke-HypercallRaw 0x0053 -InputData $bytes -OutputSize 24

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [uint32]$CallCode,

        [Parameter(Position = 1)]
        [object]$InputData,

        [uint32]$OutputSize = 0x1000,

        [switch]$IsFast,
        [uint32]$CountOfElements = 0,
        [uint32]$RepStartIndex = 0,
        [switch]$IsNested
    )

    # --- Serialize input to [byte[]] ---
    $inputBytes = if ($null -eq $InputData) {
        [byte[]]::new(0)
    }
    elseif ($InputData -is [byte[]]) {
        $InputData
    }
    elseif ($InputData -is [System.Collections.Specialized.OrderedDictionary] -or
            $InputData -is [object[]]) {
        $items = if ($InputData -is [System.Collections.Specialized.OrderedDictionary]) {
            $InputData.Values
        } else { $InputData }
        $buf = [System.IO.MemoryStream]::new()
        foreach ($val in $items) {
            $b = ConvertTo-HypercallBytes $val
            $buf.Write($b, 0, $b.Length)
        }
        $buf.ToArray()
    }
    else {
        throw "InputData must be [ordered]@{}, typed array, or [byte[]]"
    }

    # --- Call C# (all buffer management is in InvokeHypercallBytes) ---
    $r = [Hvlibdotnet.Hvlib]::InvokeHypercallBytes(
        $CallCode, $inputBytes, $OutputSize,
        [bool]$IsFast, $CountOfElements, $RepStartIndex, [bool]$IsNested)

    [PSCustomObject]@{
        Ok          = $r.Ok
        OutputBytes = $r.OutputData
    }
}


function Invoke-Hypercall {
    <#
    .SYNOPSIS
    Invoke any Hyper-V hypercall by name with named parameters.

    .DESCRIPTION
    Looks up the hypercall code by name, parses -Field Value pairs from remaining
    arguments, serializes them (native value types determine byte width), and
    delegates to Invoke-HypercallRaw.

    Name lookup order:
      1. Exact match              "HvCallEnableVpVtl"
      2. "HvCall" + Name         "EnableVpVtl"
      3. Insert "Call" after Hv  "HvEnableVpVtl" -> "HvCallEnableVpVtl"

    Fields are serialized in the order given. Native value type determines width:
      [uint64] / [int64]  -> 8 bytes    [uint32] / [int32] -> 4 bytes
      [uint16] / [int16]  -> 2 bytes    [byte]              -> 1 byte
      [byte[]]            -> raw

    Variables that are already typed (e.g. $ctx.PartitionId as [uint64]) need no cast.
    Bare integer literals (1, 0xFF) are [int32] = 4 bytes — cast when 8 bytes needed.

    .PARAMETER Name
    Hypercall name: "HvCallEnableVpVtl", "EnableVpVtl", or "HvEnableVpVtl".

    .PARAMETER Out
    Output buffer size in bytes (default 0 = 4096 via Invoke-HypercallRaw).

    .PARAMETER Rep
    Rep count for rep hypercalls (CountOfElements).

    .PARAMETER Rest
    -Field Value pairs for the input struct, in struct field order.

    .EXAMPLE
    Invoke-Hypercall HvCallEnableVpVtl -PartitionId $ctx.PartitionId -VpIndex ([uint32]0) -TargetVtl ([uint32]1)

    .EXAMPLE
    Invoke-Hypercall EnableVpVtl -PartitionId $ctx.PartitionId -VpIndex ([uint32]0) -TargetVtl ([uint32]1)

    .EXAMPLE
    Invoke-Hypercall HvCallModifyVtlProtectionMask `
        -PartitionId ([uint64]$ctx.PartitionId) -MapFlags ([uint32]7) `
        -TargetVtl ([uint32]0) -GpaPageNumber ([uint64]$gpa) -Rep 1

    .EXAMPLE
    Invoke-Hypercall HvCallGetLogicalProcessorRunTime -Out 32

    .EXAMPLE
    Invoke-Hypercall HvCallPerfNop

    .EXAMPLE
    Invoke-Hypercall HvCallSomethingNew -Field1 ([uint64]$val) -Field2 ([uint32]1)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)]
        [string]$Name,

        [int]$Out = 0,
        [int]$Rep = 0,

        [Parameter(ValueFromRemainingArguments)]
        [object[]]$Rest
    )

    # ── 1. Resolve call code ──────────────────────────────────────────────────
    $code = $Script:HvCallCode[$Name]
    if (-not $code) { $code = $Script:HvCallCode["HvCall$Name"] }
    if (-not $code -and $Name -match '^Hv(.+)') {
        $code = $Script:HvCallCode["HvCall$($Matches[1])"]
    }
    if (-not $code) {
        Write-Error "Unknown hypercall: '$Name'"
        return $null
    }

    # ── 2. Parse -Key Value pairs from $Rest ─────────────────────────────────
    $fields = [ordered]@{}
    $i = 0
    while ($i -lt $Rest.Count) {
        $token = $Rest[$i]
        if ($token -is [string] -and $token.StartsWith('-')) {
            $key = $token.TrimStart('-')
            $isNextValue = ($i + 1) -lt $Rest.Count -and
                           -not ($Rest[$i + 1] -is [string] -and $Rest[$i + 1].StartsWith('-'))
            if ($isNextValue) {
                $fields[$key] = $Rest[$i + 1]
                $i += 2
            } else {
                $fields[$key] = [uint64]0
                $i++
            }
        } else { $i++ }
    }

    # ── 3. No fields — simple call ────────────────────────────────────────────
    if ($fields.Count -eq 0) {
        return Invoke-HypercallRaw $code -OutputSize $Out -CountOfElements $Rep
    }

    # ── 4. Serialize — native value types determine byte width ───────────────
    $buf = [System.IO.MemoryStream]::new()
    foreach ($v in $fields.Values) {
        $b = ConvertTo-HypercallBytes $v
        $buf.Write($b, 0, $b.Length)
    }

    Invoke-HypercallRaw $code $buf.ToArray() -OutputSize $Out -CountOfElements $Rep
}

#endregion

#
# Other samples
#

# ==============================================================================
# region Typed hypercall wrappers (TLFS-based)
#
# Each function maps 1:1 to a Hyper-V hypercall from the TLFS.
# Parameters are named after the TLFS struct fields.
# Internally they call Invoke-HypercallRaw (generic) -> InvokeHypercallBytes (C#).
# ==============================================================================

function Invoke-HvCallReadGpa {
    <#
    .SYNOPSIS
    HvCallReadGpa (0x0053) — read up to 16 bytes from guest physical address.

    .DESCRIPTION
    Reads memory from a guest physical address using the HvCallReadGpa hypercall.
    Returns a typed object with AccessResult and Data fields.

    TLFS reference: [TLFS-MemoryAccess]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallReadGpa

    Input:  HV_INPUT_READ_GPA  { PartitionId(8), VpIndex(4), ByteCount(4), BaseGpa(8), ControlFlags(8) }
    Output: HV_OUTPUT_READ_GPA { AccessResult(8), Data[16] }

    .PARAMETER PartitionId
    Target partition ID.
    .PARAMETER BaseGpa
    Guest physical address to read from.
    .PARAMETER ByteCount
    Number of bytes to read (1-16, default 16).
    .PARAMETER VpIndex
    Virtual processor index (default 0).
    .PARAMETER ControlFlags
    Access control flags (default 0).

    .EXAMPLE
    $r = Invoke-HvCallReadGpa -PartitionId 3 -BaseGpa 0x100400000
    $r.Data | Format-Hex

    .EXAMPLE
    $r = Invoke-HvCallReadGpa -PartitionId 3 -BaseGpa $physAddr -ByteCount 8
    if ($r.Ok -and $r.AccessResult -eq 0) { "Read succeeded" }

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallReadGpa
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint64]$PartitionId,
        [Parameter(Mandatory)][uint64]$BaseGpa,
        [uint32]$ByteCount = 16,
        [uint32]$VpIndex = 0,
        [uint64]$ControlFlags = 0
    )

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallReadGpa -InputData ([ordered]@{
        PartitionId  = [uint64]$PartitionId
        VpIndex      = [uint32]$VpIndex
        ByteCount    = [uint32]$ByteCount
        BaseGpa      = [uint64]$BaseGpa
        ControlFlags = [uint64]$ControlFlags
    }) -OutputSize 24

    [PSCustomObject]@{
        Ok           = $r.Ok
        AccessResult = [BitConverter]::ToUInt64($r.OutputBytes, 0)
        Data         = [byte[]]$r.OutputBytes[8..(8 + $ByteCount - 1)]
    }
}


function Invoke-HvCallWriteGpa {
    <#
    .SYNOPSIS
    HvCallWriteGpa (0x0054) — write up to 16 bytes to guest physical address.

    .DESCRIPTION
    Writes memory to a guest physical address using the HvCallWriteGpa hypercall.

    TLFS reference: [TLFS-MemoryAccess]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallWriteGpa

    Input:  HV_INPUT_WRITE_GPA  { PartitionId(8), VpIndex(4), ByteCount(4),
                                   BaseGpa(8), ControlFlags(8), Data[16] }
    Output: HV_OUTPUT_WRITE_GPA { AccessResult(8) }

    .PARAMETER PartitionId
    Target partition ID.
    .PARAMETER BaseGpa
    Guest physical address to write to.
    .PARAMETER Data
    Byte array to write (1-16 bytes).
    .PARAMETER VpIndex
    Virtual processor index (default 0).
    .PARAMETER ControlFlags
    Access control flags (default 0).

    .EXAMPLE
    Invoke-HvCallWriteGpa -PartitionId 3 -BaseGpa 0x100400000 -Data @(0x90, 0x90)

    .EXAMPLE
    $r = Invoke-HvCallWriteGpa -PartitionId 3 -BaseGpa $gpa -Data $bytes
    if ($r.Ok -and $r.AccessResult -eq 0) { "Write succeeded" }

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallWriteGpa
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint64]$PartitionId,
        [Parameter(Mandatory)][uint64]$BaseGpa,
        [Parameter(Mandatory)][byte[]]$Data,
        [uint32]$VpIndex = 0,
        [uint64]$ControlFlags = 0
    )

    $byteCount = [Math]::Min($Data.Length, 16)
    $padded = [byte[]]::new(16)
    [Array]::Copy($Data, $padded, $byteCount)

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallWriteGpa -InputData ([ordered]@{
        PartitionId  = [uint64]$PartitionId
        VpIndex      = [uint32]$VpIndex
        ByteCount    = [uint32]$byteCount
        BaseGpa      = [uint64]$BaseGpa
        ControlFlags = [uint64]$ControlFlags
        Data         = [byte[]]$padded
    }) -OutputSize 8

    [PSCustomObject]@{
        Ok           = $r.Ok
        AccessResult = [BitConverter]::ToUInt64($r.OutputBytes, 0)
    }
}


function Invoke-HvCallGetPartitionId {
    <#
    .SYNOPSIS
    HvCallGetPartitionId (0x0046) — get the partition ID of the calling partition.

    .DESCRIPTION
    Returns the partition ID. No input parameters required.

    TLFS reference: [TLFS-PartitionId]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetPartitionId

    Output: HV_OUTPUT_GET_PARTITION_ID { PartitionId(8) }

    .EXAMPLE
    $r = Invoke-HvCallGetPartitionId
    $r.PartitionId

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetPartitionId
    #>
    [CmdletBinding()]
    param()

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallGetPartitionId -OutputSize 8

    [PSCustomObject]@{
        Ok          = $r.Ok
        PartitionId = [BitConverter]::ToUInt64($r.OutputBytes, 0)
    }
}


function Invoke-HvCallGetVpRegisters {
    <#
    .SYNOPSIS
    HvCallGetVpRegisters (0x0050) — read virtual processor registers.

    .DESCRIPTION
    Reads one or more VP registers via hypercall. This is a rep hypercall
    where CountOfElements = number of register names in the input.

    TLFS reference: [TLFS-VpRegisters]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetVpRegisters

    Input header:      { PartitionId(8), VpIndex(4), TargetVtl(1), Padding(3) }  = 16 bytes
    Rep input element: { RegisterName(4) }  for each register
    Rep output element:{ RegisterValue(16) } for each register (HV_REGISTER_VALUE is 128-bit)

    Common register codes (HV_REGISTER_NAME) [TLFS-Appendix]:
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv-register-name

      RIP  = 0x00020000    RFLAGS = 0x00020001    RSP  = 0x00020002
      RAX  = 0x00020003    RCX    = 0x00020004    RDX  = 0x00020005
      RBX  = 0x00020006    RBP    = 0x00020007    RSI  = 0x00020008
      RDI  = 0x00020009    CR0    = 0x00020012    CR3  = 0x00020014
      CR4  = 0x00020015    DR0    = 0x00020017

    .PARAMETER PartitionId
    Target partition ID.
    .PARAMETER VpIndex
    Virtual processor index.
    .PARAMETER RegisterNames
    Array of register codes (uint32).
    .PARAMETER Vtl
    Target Virtual Trust Level (default 0).

    .EXAMPLE
    $r = Invoke-HvCallGetVpRegisters -PartitionId 3 -VpIndex 0 -RegisterNames @(0x20000, 0x20002)
    "RIP = 0x{0:X}" -f $r.Values[0]
    "RSP = 0x{0:X}" -f $r.Values[1]

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallGetVpRegisters
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint64]$PartitionId,
        [uint32]$VpIndex = 0,
        [Parameter(Mandatory)][uint32[]]$RegisterNames,
        [byte]$Vtl = 0
    )

    $count = $RegisterNames.Length
    # Header: PartitionId(8) + VpIndex(4) + Vtl(1) + Padding(3) = 16 bytes
    # + RegisterName(4) * count
    $buf = [System.IO.MemoryStream]::new()
    $buf.Write([BitConverter]::GetBytes([uint64]$PartitionId), 0, 8)
    $buf.Write([BitConverter]::GetBytes([uint32]$VpIndex), 0, 4)
    $buf.WriteByte($Vtl)
    $buf.Write([byte[]]::new(3), 0, 3)  # padding
    foreach ($regName in $RegisterNames) {
        $buf.Write([BitConverter]::GetBytes([uint32]$regName), 0, 4)
    }

    # Output: 16 bytes per register (HV_REGISTER_VALUE is 128-bit)
    $outSize = $count * 16

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallGetVpRegisters `
        -InputData $buf.ToArray() -OutputSize $outSize -CountOfElements $count

    $values = [uint64[]]::new($count)
    for ($i = 0; $i -lt $count; $i++) {
        $values[$i] = [BitConverter]::ToUInt64($r.OutputBytes, $i * 16)
    }

    [PSCustomObject]@{
        Ok     = $r.Ok
        Values = $values
    }
}


function Invoke-HvCallSetVpRegisters {
    <#
    .SYNOPSIS
    HvCallSetVpRegisters (0x0051) — write virtual processor registers.

    .DESCRIPTION
    Writes one or more VP registers via hypercall. Rep hypercall.

    TLFS reference: [TLFS-VpRegisters]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSetVpRegisters

    Input header:      { PartitionId(8), VpIndex(4), TargetVtl(1), Padding(3) } = 16 bytes
    Rep input element: { RegisterName(4), Padding(4), RegisterValue(16) } = 24 bytes each

    .PARAMETER PartitionId
    Target partition ID.
    .PARAMETER VpIndex
    Virtual processor index.
    .PARAMETER Registers
    Array of hashtables: @{ Name=[uint32]; Value=[uint64] }
    .PARAMETER Vtl
    Target Virtual Trust Level (default 0).

    .EXAMPLE
    Invoke-HvCallSetVpRegisters -PartitionId 3 -VpIndex 0 -Registers @(
        @{ Name=0x20000; Value=0xFFFFF80000000000 }  # Set RIP
    )

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSetVpRegisters
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint64]$PartitionId,
        [uint32]$VpIndex = 0,
        [Parameter(Mandatory)][hashtable[]]$Registers,
        [byte]$Vtl = 0
    )

    $count = $Registers.Length
    $buf = [System.IO.MemoryStream]::new()
    # Header
    $buf.Write([BitConverter]::GetBytes([uint64]$PartitionId), 0, 8)
    $buf.Write([BitConverter]::GetBytes([uint32]$VpIndex), 0, 4)
    $buf.WriteByte($Vtl)
    $buf.Write([byte[]]::new(3), 0, 3)  # padding
    # Rep elements: Name(4) + Pad(4) + Value(16)
    foreach ($reg in $Registers) {
        $buf.Write([BitConverter]::GetBytes([uint32]$reg.Name), 0, 4)
        $buf.Write([byte[]]::new(4), 0, 4)  # padding
        $buf.Write([BitConverter]::GetBytes([uint64]$reg.Value), 0, 8)
        $buf.Write([byte[]]::new(8), 0, 8)  # high 64 bits of 128-bit value
    }

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallSetVpRegisters `
        -InputData $buf.ToArray() -CountOfElements $count

    [PSCustomObject]@{
        Ok = $r.Ok
    }
}


function Invoke-HvCallTranslateVirtualAddress {
    <#
    .SYNOPSIS
    HvCallTranslateVirtualAddress (0x0052) — translate GVA to GPA.

    .DESCRIPTION
    Translates a guest virtual address to a guest physical address
    using the hypervisor's page table walker.

    TLFS reference: [TLFS-VA]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallTranslateVirtualAddress

    Input:  { PartitionId(8), VpIndex(4), Padding(4), ControlFlags(8), GvaPage(8) }
    Output: { TranslationResult(8), GpaPage(8) }

    .PARAMETER PartitionId
    Target partition ID.
    .PARAMETER GvaPage
    Guest virtual address (page-aligned; bits [11:0] ignored by hypervisor).
    .PARAMETER VpIndex
    Virtual processor index (default 0).
    .PARAMETER ControlFlags
    Translation control flags (default 0). Bit 0 = validate read, Bit 1 = validate write.

    .EXAMPLE
    $r = Invoke-HvCallTranslateVirtualAddress -PartitionId 3 -GvaPage 0xFFFFF80000000000
    if ($r.Ok) { "GPA = 0x{0:X}" -f $r.GpaPage }

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallTranslateVirtualAddress
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint64]$PartitionId,
        [Parameter(Mandatory)][uint64]$GvaPage,
        [uint32]$VpIndex = 0,
        [uint64]$ControlFlags = 0
    )

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallTranslateVirtualAddress -InputData ([ordered]@{
        PartitionId  = [uint64]$PartitionId
        VpIndex      = [uint32]$VpIndex
        Padding      = [uint32]0
        ControlFlags = [uint64]$ControlFlags
        GvaPage      = [uint64]$GvaPage
    }) -OutputSize 16

    [PSCustomObject]@{
        Ok                = $r.Ok
        TranslationResult = [BitConverter]::ToUInt64($r.OutputBytes, 0)
        GpaPage           = [BitConverter]::ToUInt64($r.OutputBytes, 8)
    }
}


function Invoke-HvCallPostMessage {
    <#
    .SYNOPSIS
    HvCallPostMessage (0x005C) — post a message to a connection port.

    .DESCRIPTION
    Posts a message to a Hyper-V connection port (SynIC messaging).

    TLFS reference: [TLFS-SynIC]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallPostMessage

    Input: { ConnectionId(4), Padding(4), MessageType(4), PayloadSize(4), Payload[240] }
    No output data (status only).

    .PARAMETER ConnectionId
    Target connection ID.
    .PARAMETER MessageType
    Message type identifier.
    .PARAMETER Payload
    Message payload (up to 240 bytes).

    .EXAMPLE
    Invoke-HvCallPostMessage -ConnectionId 1 -MessageType 1 -Payload @(1,2,3,4)

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallPostMessage
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$ConnectionId,
        [Parameter(Mandatory)][uint32]$MessageType,
        [byte[]]$Payload = @()
    )

    $payloadSize = [Math]::Min($Payload.Length, 240)
    $padded = [byte[]]::new(240)
    if ($payloadSize -gt 0) { [Array]::Copy($Payload, $padded, $payloadSize) }

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallPostMessage -InputData ([ordered]@{
        ConnectionId = [uint32]$ConnectionId
        Padding      = [uint32]0
        MessageType  = [uint32]$MessageType
        PayloadSize  = [uint32]$payloadSize
        Payload      = [byte[]]$padded
    })

    [PSCustomObject]@{
        Ok = $r.Ok
    }
}


function Invoke-HvCallSignalEvent {
    <#
    .SYNOPSIS
    HvCallSignalEvent (0x005D) — signal a Hyper-V event connection.

    .DESCRIPTION
    Signals an event on a SynIC event connection.

    TLFS reference: [TLFS-SynIC]
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSignalEvent

    Input: { ConnectionId(4), FlagNumber(2), Padding(2) }
    No output data.

    .PARAMETER ConnectionId
    Target connection ID.
    .PARAMETER FlagNumber
    Event flag number (0-2047).

    .EXAMPLE
    Invoke-HvCallSignalEvent -ConnectionId 1 -FlagNumber 0

    .LINK
    https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercalls/HvCallSignalEvent
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$ConnectionId,
        [uint16]$FlagNumber = 0
    )

    $r = Invoke-HypercallRaw -CallCode $Script:HvCallCode.HvCallSignalEvent -InputData ([ordered]@{
        ConnectionId = [uint32]$ConnectionId
        FlagNumber   = [uint16]$FlagNumber
        Padding      = [uint16]0
    })

    [PSCustomObject]@{
        Ok = $r.Ok
    }
}

#endregion


# ==============================================================================
# Module Export
# ==============================================================================

# Export $HvCallCode so callers can use: $HvCallCode.ReadGpa, $HvCallCode.WriteGpa, etc.
# Note: Export-ModuleMember -Variable exports $Script:HvCallCode into caller's scope.

Export-ModuleMember -Function @(
    # Generic
    'Invoke-Hypercall',
    'Invoke-HypercallRaw',
    # Typed (TLFS)
    'Invoke-HvCallReadGpa',
    'Invoke-HvCallWriteGpa',
    'Invoke-HvCallGetPartitionId',
    'Invoke-HvCallGetVpRegisters',
    'Invoke-HvCallSetVpRegisters',
    'Invoke-HvCallTranslateVirtualAddress',
    'Invoke-HvCallPostMessage',
    'Invoke-HvCallSignalEvent'
) -Variable @(
    'HvCallCode'
)

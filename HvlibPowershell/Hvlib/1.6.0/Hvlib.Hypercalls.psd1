# ==============================================================================
# Module Manifest: Hvlib.Hypercalls.psd1
# Version:         1.0.0
# Description:     Typed Hyper-V hypercall wrappers based on TLFS
# ==============================================================================

@{
    RootModule        = 'Hvlib.Hypercalls.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'D4E8F1A2-7B3C-4D9E-A5F6-2C8E1D3B5A7F'
    Author            = 'Arthur Khudyaev (@gerhart_x)'
    CompanyName       = ''
    Copyright         = '(c) All rights reserved'

    Description       = 'Typed Hyper-V hypercall wrappers based on the Top Level Functional Specification (TLFS). Provides PowerShell cmdlets for HvCallReadGpa, HvCallWriteGpa, HvCallGetVpRegisters, HvCallTranslateVirtualAddress, and other hypercalls, plus a generic Invoke-Hypercall for arbitrary hypercall codes.'

    PowerShellVersion = '7.0'

    # Requires Hvlib module (for [Hvlibdotnet.Hvlib]::InvokeHypercallBytes)
    RequiredModules   = @('Hvlib')

    FunctionsToExport = @(
        # Generic hypercall interface (DSL: by name + -Field Value pairs)
        'Invoke-Hypercall',
        # Low-level interface (by code + byte[]/ordered/@{})
        'Invoke-HypercallRaw',
        # Typed TLFS wrappers
        'Invoke-HvCallReadGpa',           # 0x0053
        'Invoke-HvCallWriteGpa',          # 0x0054
        'Invoke-HvCallGetPartitionId',    # 0x0046
        'Invoke-HvCallGetVpRegisters',    # 0x0050
        'Invoke-HvCallSetVpRegisters',    # 0x0051
        'Invoke-HvCallTranslateVirtualAddress',  # 0x0052
        'Invoke-HvCallPostMessage',       # 0x005C
        'Invoke-HvCallSignalEvent'        # 0x005D
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    FileList = @(
        'Hvlib.Hypercalls.psm1',
        'Hvlib.Hypercalls.psd1'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @('Hyper-V', 'Hypercall', 'TLFS', 'Virtualization', 'Memory')
            ProjectUri   = 'https://github.com/gerhart01/Hyper-V-Tools'
            ReleaseNotes = @'
Version 1.0.0 (Initial Release)
- Invoke-Hypercall: generic hypercall with auto-serialization ([ordered]@{}, array, byte[])
- Invoke-HvCallReadGpa (0x0053): read up to 16 bytes from guest physical address
- Invoke-HvCallWriteGpa (0x0054): write up to 16 bytes to guest physical address
- Invoke-HvCallGetPartitionId (0x0046): get partition ID
- Invoke-HvCallGetVpRegisters (0x0050): read VP registers (rep hypercall)
- Invoke-HvCallSetVpRegisters (0x0051): write VP registers (rep hypercall)
- Invoke-HvCallTranslateVirtualAddress (0x0052): GVA to GPA translation
- Invoke-HvCallPostMessage (0x005C): post SynIC message
- Invoke-HvCallSignalEvent (0x005D): signal SynIC event
- All input/output structures based on Microsoft TLFS
- References: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
'@
        }
    }
}

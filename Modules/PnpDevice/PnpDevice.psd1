﻿@{
    GUID = 'ad34bc8b-1cf8-47d8-bd82-f681c5358e1c'
    Author = "Microsoft Corporation"
    CompanyName = "Microsoft Corporation"
    Copyright = "© Microsoft Corporation. All rights reserved."
    ModuleVersion = '1.0.0.0'
    PowerShellVersion = '5.1'
    HelpInfoUri="https://aka.ms/winsvr-2022-pshelp"
    NestedModules = @(
        'PnpDevice.cdxml')
    TypesToProcess = @(
        'PnpDevice.Types.ps1xml')
    FormatsToProcess = @(
        'PnpDevice.format.ps1xml')
    FileList = @(
        'PnpDevice.cdxml',
        'PnpDevice.Types.ps1xml',
        'PnpDevice.format.ps1xml',
        'PnpDevice.Resource.psd1')
    AliasesToExport = @()
    CmdletsToExport = @()
    FunctionsToExport = @(
        'Get-PnpDevice',
        'Get-PnpDeviceProperty',
        'Enable-PnpDevice',
        'Disable-PnpDevice')
    CompatiblePSEditions = @('Desktop', 'Core')
}

[CmdletBinding()]
Param
(
    [switch]$BuildHTMLReport
)

$SchannelRootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$TLSVersions = @("1.0","1.1","1.2","1.3")
$SchannelTLSSubKeys =  @("Client","Server")
$SchannelProtocolRegNames = @("Enabled","DisabledByDefault")
$FrameworkRootKeys = @("HKLM:\SOFTWARE\Microsoft\.NETFramework","HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework")
$FrameworkVersions = @("v4.0.30319","v2.0.50727")
$FrameworkValues = @("SystemDefaultTlsVersions","SchUseStrongCrypto")
$UndefinedInfo = "Description of 'Undefined': No Registry values were found. In this case the OS Version defaults apply.`nFor further information navigate to 'https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-#tls-protocol-version-support'.`n`n"
$Title = "Status of TLS protocols for Computer: $($env:COMPUTERNAME)"

# Initialize table for TLS settings
$TLStable = New-Object system.Data.DataTable
$newcol = New-Object system.Data.DataColumn "Version",([string]); $TLStable.columns.add($newcol)
$newcol = New-Object system.Data.DataColumn $TLSVersions[0],([string]); $TLStable.columns.add($newcol)
$newcol = New-Object system.Data.DataColumn $TLSVersions[1],([string]); $TLStable.columns.add($newcol)
$newcol = New-Object system.Data.DataColumn $TLSVersions[2],([string]); $TLStable.columns.add($newcol)
$newcol = New-Object system.Data.DataColumn $TLSVersions[3],([string]); $TLStable.columns.add($newcol)
$row1 = $TLStable.NewRow()
$row1.Version = "Client"
$TLStable.Rows.Add($row1)
$row2 = $TLStable.NewRow()
$row2.Version = "Server"
$TLStable.Rows.Add($row2)

# Initialize table for .NET settings
$NETtable = New-Object system.Data.DataTable
$newcol = New-Object system.Data.DataColumn "Version",([string]); $NETTable.columns.add($newcol)
$newcol = New-Object system.Data.DataColumn $FrameworkVersions[0],([string]); $NETTable.columns.add($newcol)
$newcol = New-Object system.Data.DataColumn $FrameworkVersions[1],([string]); $NETTable.columns.add($newcol)
$row1 = $NETTable.NewRow()
$row1.Version = "Status"
$NETTable.Rows.Add($row1)

function Get-RegValue
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $regpath,
        [Parameter(Mandatory = $true)]
        [string]
        $regname
    )

    $regItem = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Ignore
    $output = "" | Select-Object Name, Value
    $output.Name = $RegName

    If ($null -eq $regItem)
    {
        $output.Value = "Not Found"
    }

    Else
    {
        $output.Value = $regItem.$RegName
    }

    Return $output
}

Function Get-ProtocolStatus {
    [CmdletBinding()]
    Param
    (
        # Registry Path
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "TLS")]
        [string]
        $RegPath,
        [Parameter(Position = 1, ParameterSetName = "TLS")]
        [switch]$TLS,
        [Parameter(Position = 2, ParameterSetName = "Framework")]
        [ValidateSet("v2.0.50727","v4.0.30319")]
        [string]$FrameworkVersion
    )

    if ($TLS)
    {
        [Array]$regnames = $SchannelProtocolRegNames
    }

    else
    {
        [Array]$regnames = $FrameworkValues
    }

    [array]$RegNameValues = @()
    $RegNameValues = foreach ($RegName in $regnames)
    {
        if ($FrameworkVersion)
        {
            foreach ($key in $FrameworkRootKeys)
            {
                $FrameworkVersionPath = Join-Path -Path $Key -ChildPath $FrameworkVersion
                Get-RegValue -regpath $FrameworkVersionPath -regname $RegName
            }
        }

        else
        {
            Get-RegValue -regpath $RegPath -regname $RegName
        }
    }

    if ($RegNameValues.Value[0] -eq 1 -and $RegNameValues.Value[1] -eq 0 -and $TLS)
    {
        $ProtocolStatus = "Enabled"
    }

    elseif ($RegNameValues.Value[0] -eq 0 -and $RegNameValues.Value[1] -eq 1 -and $TLS)
    {
        $ProtocolStatus = "Disabled"
    }

    elseif ($RegNameValues.Value[0] -eq 1 -and $RegNameValues.Value[1] -eq 1 -and $RegNameValues.Value[2] -eq 1 -and $RegNameValues.Value[3] -eq 1 -and $FrameworkVersion)
    {
        $ProtocolStatus = "Enabled"
    }

    elseif ($RegNameValues.Value[0] -eq 0 -and $RegNameValues.Value[1] -eq 0 -and $RegNameValues.Value[2] -eq 0 -and $RegNameValues.Value[3] -eq 0-and $FrameworkVersion)
    {
        $ProtocolStatus = "Disabled"
    }

    elseif ($RegNameValues.Value[0] -eq "Not found" -or $RegNameValues.Value[1] -eq "Not found")
    {
        $ProtocolStatus = "Undefined"
    }

    elseif ($RegNameValues.Value[0] -eq "Not found" -or $RegNameValues.Value[1] -eq "Not found" -or $RegNameValues.Value[2] -eq "Not found" -or $RegNameValues.Value[3] -eq "Not found" -and $FrameworkVersion)
    {
        $ProtocolStatus = "Undefined"
    }

    else
    {
        $ProtocolStatus = "Invalid"    
    }

    if ($ProtocolStatus -eq "Undefined")
    {
        $Script:ShowUndefinedInfo = $true
    }

    Return $ProtocolStatus
}

# Enumerate TLS Versions
foreach ($Version in $TLSVersions)
{
    $TLSVersionKey = Join-Path -Path $SchannelRootKey -ChildPath ("TLS " + $($Version))

    foreach ($Subkey in $SchannelTLSSubKeys)
    {
        $TLSVersionSubKey = Join-Path -Path $TLSVersionKey -ChildPath $Subkey
        $CurrentRow = $TLStable.Rows | Where-Object Version -EQ $Subkey
        $ProtocolStatus = Get-ProtocolStatus -RegPath $TLSVersionSubKey -TLS
        $CurrentRow.$Version = $ProtocolStatus
    }
}

# Enumerate .NET Framework TLS status
$NETv2Status = Get-ProtocolStatus -FrameworkVersion "v2.0.50727"
$NETv4Status = Get-ProtocolStatus -FrameworkVersion "v4.0.30319"
$CurrentRow = $NETtable.Rows.Item(0)
$CurrentRow.'v2.0.50727' = $NETv2Status
$CurrentRow.'v4.0.30319' = $NETv4Status

# Write Output to screen
Clear-Host
Write-Host -ForegroundColor Cyan -Object "`n$($Title)`n"
Write-Host -ForegroundColor DarkYellow -Object "TLS Versions"
$TLStable | ft -AutoSize
Write-Host -ForegroundColor DarkYellow -Object ".NET Framework"
$NETtable | ft -AutoSize
if ($Script:ShowUndefinedInfo)
{
    Write-Host -ForegroundColor DarkYellow -Object $UndefinedInfo
}

if ($BuildHTMLReport)
{
$header = @"
    <style>
    h1 {
        font-family: Arial, Helvetica, sans-serif;
        color: #0d0000;
        font-size: 28px;
    }
    
    h2 {
        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;
    }
    
    table {
        font-size: 12px;
        border: 0px; 
        font-family: Arial, Helvetica, sans-serif;
    } 
    
    td {
        padding: 4px;
        margin: 0px;
        border: 0;
        text-align: center;
    }
    
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
    }

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

    #PostContent {
        font-family: Arial, Helvetica, sans-serif;
        color: #018729;
        font-size: 12px;
    }

    .DisabledStatus {
        color: #ff0000;
    }
    
    .EnabledStatus {
        color: #008000;
    }
    
    .UndefinedStatus {
        color: #c74402
    }
    </style>
"@
    
    $outputfile = Join-Path -Path $PSScriptRoot -ChildPath "TLS-Statusreport.html"
    $Heading = "<h1>$($Title)</h1>"
    $TLShtmltable = $TLStable | Select-Object Version,"1.0","1.1","1.2","1.3" | ConvertTo-Html -Fragment -PreContent "<h2>TLS Versions</h2>"
    $TLShtmltable = $TLShtmltable -replace '<td>Undefined</td>','<td class="UndefinedStatus">Undefined</td>'
    $TLShtmltable = $TLShtmltable -replace '<td>Disabled</td>','<td class="DisabledStatus">Disabled</td>' 
    $TLShtmltable = $TLShtmltable -replace '<td>Enabled</td>','<td class="EnabledStatus">Enabled</td>' 
    $NEThtmltable = $NETtable | Select-Object Version,"v2.0.50727","v4.0.30319" | ConvertTo-Html -Fragment -PreContent "<h2>.NET Framework</h2>"
    $NEThtmltable = $NEThtmltable -replace '<td>Undefined</td>','<td class="UndefinedStatus">Undefined</td>'
    $NEThtmltable = $NEThtmltable -replace '<td>Disabled</td>','<td class="DisabledStatus">Disabled</td>' 
    $NEThtmltable = $NEThtmltable -replace '<td>Enabled</td>','<td class="EnabledStatus">Enabled</td>' 
    $body = "$Heading $tlshtmltable $nethtmltable"
    if ($Script:ShowUndefinedInfo)
    {
        $postContent = "<p id='PostContent'>$($UndefinedInfo)</p>"
    }

    $Report = ConvertTo-Html -Body $body -Title $Title -Head $header -PostContent $postContent
    $report | Out-File -FilePath $outputfile
}
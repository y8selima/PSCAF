#requires -Version 5.1
<#
.SYNOPSIS
    Collects detailed information about running processes for compromise assessment.
.DESCRIPTION
    Part of the PowerShell Compromise Assessment Framework.
    Collects process details, loaded modules, network connections, and builds process trees.
.PARAMETER OutputPath
    Path where the collected artifacts will be stored.
.PARAMETER QuickScan
    Performs a quick scan by disabling module collection, handle collection, command line collection, and process tree building.
.PARAMETER IncludeModules
    Whether to include loaded module information. Default is $true.
.PARAMETER IncludeHandles
    Whether to include handle information. Default is $false.
.PARAMETER IncludeCommandLine
    Whether to include command line information. Default is $true.
.PARAMETER BuildProcessTree
    Whether to build and include the process tree. Default is $true.
.PARAMETER MaxModulesPerProcess
    Maximum number of modules to collect per process. Default is 100.
.PARAMETER FilterSystem
    Whether to filter out common system processes. Default is $false.
.EXAMPLE
    .\ProcessCollector.ps1 -OutputPath "C:\compromise_assessment\Process_collector" -QuickScan
.EXAMPLE
    .\ProcessCollector.ps1 -OutputPath "C:\compromise_assessment\Process_collector" -IncludeModules:$false -IncludeHandles:$false
.NOTES
    Author: yasser.magdy102030@gmail.com
    Version: 1.0
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$QuickScan,
    
    [Parameter(Mandatory = $false)]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeModules = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeHandles = $false,
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeCommandLine = $true,
    
    [Parameter(Mandatory = $false)]
    [bool]$BuildProcessTree = $true,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxModulesPerProcess = 100,
    
    [Parameter(Mandatory = $false)]
    [bool]$FilterSystem = $false
)


if ($QuickScan) {
    Write-Host "QuickScan enabled. Setting optimized collection parameters." -ForegroundColor Yellow
    $IncludeModules = $false
    $IncludeHandles = $false
    $IncludeCommandLine = $false
    $BuildProcessTree = $false
    $FilterSystem = $true
}


$CollectionTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFilePath = Join-Path -Path $OutputPath -ChildPath "ProcessCollection_Log_$CollectionTimestamp.log"
$ProcessesOutputPath = Join-Path -Path $OutputPath -ChildPath "Processes_$CollectionTimestamp.json"
$ProcessTreeOutputPath = Join-Path -Path $OutputPath -ChildPath "ProcessTree_$CollectionTimestamp.json"
$ModulesOutputPath = Join-Path -Path $OutputPath -ChildPath "ProcessModules_$CollectionTimestamp.json"
$HandlesOutputPath = Join-Path -Path $OutputPath -ChildPath "ProcessHandles_$CollectionTimestamp.json"
$NetworkOutputPath = Join-Path -Path $OutputPath -ChildPath "ProcessNetwork_$CollectionTimestamp.json"
$SummaryOutputPath = Join-Path -Path $OutputPath -ChildPath "Summary_$CollectionTimestamp.json"
$CollectionResults = @{}
$SystemProcesses = @(
    "svchost.exe", "System", "smss.exe", "csrss.exe", "wininit.exe", 
    "services.exe", "lsass.exe", "winlogon.exe", "explorer.exe", "dwm.exe", 
    "spoolsv.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe", "SearchUI.exe", 
    "sihost.exe", "taskhostw.exe", "ctfmon.exe", "smartscreen.exe", "dllhost.exe", 
    "conhost.exe", "fontdrvhost.exe", "SearchIndexer.exe", "WmiPrvSE.exe"
)


function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    try {
        $logEntry | Out-File -FilePath $LogFilePath -Append -Encoding UTF8
    }
    catch {
        Write-Warning "Unable to write to log file: $($_.Exception.Message)"
    }
    
    switch ($Level) {
        "Info"    { Write-Host $logEntry -ForegroundColor Gray }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $logEntry -ForegroundColor Red }
        "Success" { Write-Host $logEntry -ForegroundColor Green }
    }
}

function Get-FileHash256 {
    param ([string]$FilePath)
    
    try {
        if (Test-Path -Path $FilePath -PathType Leaf) {
            $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
            return $hash.Hash
        }
        else {
            return "File not found"
        }
    }
    catch {
        return "Error calculating hash: $($_.Exception.Message)"
    }
}

function Test-FileSignature {
    param ([string]$FilePath)
    
    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        return [PSCustomObject]@{
            Path = $FilePath
            Status = "File not found"
            SignerCertificate = $null
            IsOSBinary = $false
        }
    }
    
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        
        return [PSCustomObject]@{
            Path = $FilePath
            Status = $signature.Status
            SignerCertificate = if ($signature.SignerCertificate) {
                [PSCustomObject]@{
                    Subject = $signature.SignerCertificate.Subject
                    Issuer = $signature.SignerCertificate.Issuer
                    Thumbprint = $signature.SignerCertificate.Thumbprint
                }
            } else { $null }
            IsOSBinary = $signature.IsOSBinary
        }
    }
    catch {
        return [PSCustomObject]@{
            Path = $FilePath
            Status = "Error: $($_.Exception.Message)"
            SignerCertificate = $null
            IsOSBinary = $false
        }
    }
}

function Export-ToJson {
    param (
        [Parameter(Mandatory = $true)]
        [object]$InputObject,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        if ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.IDictionary]) {
            $convertedObject = [PSCustomObject]@{}
            
            foreach ($key in $InputObject.Keys) {
                $stringKey = $key.ToString()
                $convertedObject | Add-Member -MemberType NoteProperty -Name $stringKey -Value $InputObject[$key]
            }
            
            $convertedObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $FilePath -Encoding UTF8
        }
        else {
            $InputObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $FilePath -Encoding UTF8
        }
        
        Write-Log -Message "Data exported to $FilePath" -Level "Success"
        return $true
    }
    catch {
        Write-Log -Message "Failed to export data to $FilePath : $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Initialize-OutputLocation {
    try {
        if (!(Test-Path -Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Log -Message "Created output directory: $OutputPath" -Level "Success"
        }
        $headerText = @"
=================================================
Process Collection Module
Started: $(Get-Date)
Computer: $ComputerName
=================================================
"@
        $headerText | Out-File -FilePath $LogFilePath -Encoding UTF8
        
        Write-Log -Message "Process collection initialized" -Level "Info"
        Write-Log -Message "Parameters: QuickScan=$QuickScan, IncludeModules=$IncludeModules, IncludeHandles=$IncludeHandles" -Level "Info"
        
        return $true
    }
    catch {
        Write-Warning "Failed to initialize output location: $($_.Exception.Message)"
        return $false
    }
}
function Get-ProcessDetails {
    Write-Log -Message "Collecting process details..." -Level "Info"
    Write-Host "Starting process collection..." -ForegroundColor Cyan
    $processCount = 0
    $suspiciousCount = 0
    $processes = @()
    
    try {
        Write-Host "Retrieving process list..." -ForegroundColor Cyan
        $allProcesses = Get-Process -ErrorAction Stop 
        if ($FilterSystem) {
            Write-Host "Filtering system processes..." -ForegroundColor Cyan
            $allProcesses = $allProcesses | Where-Object { $SystemProcesses -notcontains $_.Name }
            Write-Log -Message "Filtered out common system processes, remaining: $($allProcesses.Count)" -Level "Info"
            Write-Host "Found $($allProcesses.Count) non-system processes to analyze." -ForegroundColor Green
        } else {
            Write-Host "Found $($allProcesses.Count) total processes to analyze." -ForegroundColor Green
        }
        
        $processCounter = 0
        $totalProcesses = $allProcesses.Count
        $lastPercentage = 0
        Write-Host "`nProcess Collection Progress:" -ForegroundColor Cyan
        Write-Host "[" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(50, " ") -NoNewline
        Write-Host "] 0%" -ForegroundColor Cyan
        
        foreach ($process in $allProcesses) {
            $processCounter++
            $processCount++
            $percentage = [math]::Floor(($processCounter / $totalProcesses) * 100)
            if (($percentage -ge $lastPercentage + 2) -or ($totalProcesses -lt 100 -and $processCounter % 5 -eq 0) -or $processCounter -eq $totalProcesses) {
                $lastPercentage = $percentage
                $progressBarLength = [math]::Floor($percentage / 2)
                Write-Host "`r" -NoNewline
                Write-Host "[" -NoNewline -ForegroundColor Cyan
                Write-Host "".PadRight($progressBarLength, "=") -NoNewline -ForegroundColor Green
                Write-Host "".PadRight(50 - $progressBarLength, " ") -NoNewline
                Write-Host "] $percentage%" -NoNewline -ForegroundColor Cyan
                
                if ($processCounter -eq $totalProcesses) {
                    Write-Host ""
                }
            }
            
            $processPath = $null
            try {
                if ($process.Path) {
                    $processPath = $process.Path
                }
                else {
                    $processPath = "System Process"
                }
            }
            catch {
                $processPath = "Unknown (Access Denied)"
            }
            $commandLine = $null
            if ($IncludeCommandLine) {
                try {
                    $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($process.Id)'" -ErrorAction Stop
                    if ($wmiProcess) {
                        $commandLine = $wmiProcess.CommandLine
                    }
                }
                catch {
                    $commandLine = "Access Denied: $($_.Exception.Message)"
                }
            }
            $processOwner = $null
            try {
                $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($process.Id)'" -ErrorAction Stop
                if ($wmiProcess) {
                    $owner = $wmiProcess.GetOwner()
                    if ($owner.Domain -and $owner.User) {
                        $processOwner = "$($owner.Domain)\$($owner.User)"
                    }
                    else {
                        $processOwner = "Unknown"
                    }
                }
            }
            catch {
                $processOwner = "Access Denied"
            }
            $parentProcess = $null
            try {
                $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($process.Id)'" -ErrorAction Stop
                if ($wmiProcess -and $wmiProcess.ParentProcessId) {
                    $parentId = $wmiProcess.ParentProcessId
                    $parentWmi = Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$parentId'" -ErrorAction SilentlyContinue
                    
                    if ($parentWmi) {
                        $parentProcess = [PSCustomObject]@{
                            Id = $parentId
                            Name = $parentWmi.Name
                            Path = $parentWmi.ExecutablePath
                            CommandLine = if ($IncludeCommandLine) { $parentWmi.CommandLine } else { $null }
                        }
                    }
                    else {
                        $parentProcess = [PSCustomObject]@{
                            Id = $parentId
                            Name = "Unknown (Process no longer exists)"
                            Path = $null
                            CommandLine = $null
                        }
                    }
                }
            }
            catch {
                $parentProcess = [PSCustomObject]@{
                    Id = 0
                    Name = "Access Denied: $($_.Exception.Message)"
                    Path = $null
                    CommandLine = $null
                }
            }

            $fileHash = $null
            $signature = $null
            $fileInfo = $null
            
            if ($processPath -and $processPath -ne "System Process" -and $processPath -ne "Unknown (Access Denied)") {
                try {
                    $fileHash = Get-FileHash256 -FilePath $processPath
                    $signature = Test-FileSignature -FilePath $processPath
                    $item = Get-Item -Path $processPath -ErrorAction SilentlyContinue
                    if ($item) {
                        $fileInfo = [PSCustomObject]@{
                            CreationTime = $item.CreationTime
                            LastWriteTime = $item.LastWriteTime
                            LastAccessTime = $item.LastAccessTime
                            Size = $item.Length
                            FileVersion = $process.FileVersion
                            ProductVersion = $process.ProductVersion
                            Company = $process.Company
                            Description = $process.Description
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error processing file info for process $($process.Name) (ID: $($process.Id)): $($_.Exception.Message)" -Level "Warning"
                }
            }
            $isSuspicious = $false
            $suspiciousReasons = @()
            if ($processPath -eq "Unknown (Access Denied)" -and $process.Name -notin @("System", "Registry", "Memory Compression")) {
                $isSuspicious = $true
                $suspiciousReasons += "Access denied to process path"
            }
            if ($processPath -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\") {
                $isSuspicious = $true
                $suspiciousReasons += "Process running from temporary directory"
            }
            
            if ($signature -and 
                $signature.Status -ne "Valid" -and 
                $processPath -notmatch "\\Program Files\\|\\Program Files \(x86\)\\|\\Windows\\|\\System32\\") {
                $isSuspicious = $true
                $suspiciousReasons += "Unsigned executable outside of standard paths"
            }

            $processObj = [PSCustomObject]@{
                Id = $process.Id
                Name = $process.Name
                Path = $processPath
                CommandLine = $commandLine
                StartTime = $process.StartTime
                Owner = $processOwner
                CPU = $process.CPU
                WorkingSet = $process.WorkingSet64
                PrivateMemorySize = $process.PrivateMemorySize64
                VirtualMemorySize = $process.VirtualMemorySize64
                Threads = $process.Threads.Count
                Handles = $process.HandleCount
                Modules = $null  
                ModuleCount = if ($process.Modules) { $process.Modules.Count } else { 0 }
                Parent = $parentProcess
                FileHash = $fileHash
                Signature = $signature
                FileInfo = $fileInfo
                IsSuspicious = $isSuspicious
                SuspiciousReasons = $suspiciousReasons
            }
            
            if ($isSuspicious) {
                $suspiciousCount++
                Write-Log -Message "Suspicious process identified: $($process.Name) (ID: $($process.Id)) - Reasons: $($suspiciousReasons -join '; ')" -Level "Warning"
            }
            
            $processes += $processObj
        }
        
        Write-Host "`nCollected details for $processCount processes ($suspiciousCount suspicious)" -ForegroundColor Green
        Write-Log -Message "Collected details for $processCount processes ($suspiciousCount suspicious)" -Level "Success"
        return $processes
    }
    catch {
        Write-Log -Message "Error collecting process details: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting process details: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-ProcessModules {
    param ([array]$Processes)
    
    Write-Log -Message "Collecting process modules..." -Level "Info"
    $processModules = @()
    $moduleCount = 0
    $suspiciousModuleCount = 0
    
    try {
        foreach ($process in $Processes) {
            if ($process.Id -le 4) {
                continue
            }
            
            $processModuleInfo = [PSCustomObject]@{
                ProcessId = $process.Id
                ProcessName = $process.Name
                Modules = @()
                ErrorMessage = $null
            }
            
            try {
                $currentProcess = Get-Process -Id $process.Id -ErrorAction Stop
                $modules = $currentProcess.Modules | Select-Object -First $MaxModulesPerProcess
                
                foreach ($module in $modules) {
                    $moduleCount++
                    $modulePath = $module.FileName
                    $isSuspicious = $false
                    $suspiciousReasons = @()
                    if ($modulePath -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\") {
                        $isSuspicious = $true
                        $suspiciousReasons += "Module loaded from temporary directory"
                    }

                    if ($module.ModuleName -match "^\d+\.dll$" -or $module.ModuleName -match "^[a-zA-Z]{1,3}\.dll$") {
                        $isSuspicious = $true
                        $suspiciousReasons += "Unusual module name pattern"
                    }
                    
                    if ($modulePath -notmatch "\\Windows\\|\\Program Files\\|\\Program Files \(x86\)\\|\\Microsoft\.NET\\") {
                        $suspiciousReasons += "Module loaded from non-standard location"
                    }
                    $signature = $null
                    try {
                        $signature = Test-FileSignature -FilePath $modulePath
                        if ($signature.Status -ne "Valid" -and 
                            $modulePath -match "\\Windows\\System32\\|\\Windows\\SysWOW64\\") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Unsigned module in system directory"
                        }
                    }
                    catch {
                        write-host "Signature check failed"
                    }
                    
                    if ($isSuspicious) {
                        $suspiciousModuleCount++
                    }
                    $moduleObj = [PSCustomObject]@{
                        Name = $module.ModuleName
                        FileName = $modulePath
                        BaseAddress = "0x{0:X}" -f [int64]$module.BaseAddress
                        ModuleMemorySize = $module.ModuleMemorySize
                        FileVersion = $module.FileVersion
                        ProductVersion = $module.ProductVersion
                        Company = $module.Company
                        Description = $module.Description
                        Signature = $signature
                        IsSuspicious = $isSuspicious
                        SuspiciousReasons = $suspiciousReasons
                    }
                    
                    $processModuleInfo.Modules += $moduleObj
                }
                
                $suspiciousModulesInProcess = $processModuleInfo.Modules | Where-Object { $_.IsSuspicious }
                if ($suspiciousModulesInProcess -and $suspiciousModulesInProcess.Count -gt 0) {
                    Write-Log -Message "Process $($process.Name) (ID: $($process.Id)) has $($suspiciousModulesInProcess.Count) suspicious modules" -Level "Warning"
                }
            }
            catch {
                Write-Log -Message "Error collecting modules for process $($process.Name) (ID: $($process.Id)): $($_.Exception.Message)" -Level "Warning"
                $processModuleInfo.ErrorMessage = "Error: $($_.Exception.Message)"
            }
            $processModules += $processModuleInfo
        }
        
        Write-Log -Message "Collected details for $moduleCount modules across all processes ($suspiciousModuleCount suspicious)" -Level "Success"
        return $processModules
    }
    catch {
        Write-Log -Message "Error collecting process modules: $($_.Exception.Message)" -Level "Error"
        return @()
    }
}

function Get-ProcessHandles {
    param ([array]$Processes)
    
    Write-Log -Message "Collecting process handles (this may take time)..." -Level "Info"
    $processHandles = @()
    $handleCount = 0
    
    try {
        foreach ($process in $Processes) {
            if ($process.Id -le 4) {
                continue
            }
            
            try {
                $currentProcess = Get-Process -Id $process.Id -ErrorAction Stop
                $handleObj = [PSCustomObject]@{
                    ProcessId = $process.Id
                    ProcessName = $process.Name
                    HandleCount = $currentProcess.HandleCount
                    Note = "Detailed handle information requires external tools like Sysinternals Handle.exe"
                }
                
                $processHandles += $handleObj
                $handleCount += $currentProcess.HandleCount
            }
            catch {
                Write-Log -Message "Error collecting handles for process $($process.Name) (ID: $($process.Id)): $($_.Exception.Message)" -Level "Warning"
                $processHandles += [PSCustomObject]@{
                    ProcessId = $process.Id
                    ProcessName = $process.Name
                    HandleCount = 0
                    Error = "Error: $($_.Exception.Message)"
                }
            }
        }
        
        Write-Log -Message "Collected basic handle information for processes (total handles: $handleCount)" -Level "Success"
        return $processHandles
    }
    catch {
        Write-Log -Message "Error collecting process handles: $($_.Exception.Message)" -Level "Error"
        return @()
    }
}

function Get-ProcessNetwork {
    param ([array]$Processes)
    
    Write-Log -Message "Collecting process network connections..." -Level "Info"
    Write-Host "`nCollecting network connection information..." -ForegroundColor Cyan
    $processNetwork = @()
    $connectionCount = 0
    $suspiciousConnectionCount = 0
    
    try {
        Write-Host "  Retrieving TCP connections..." -ForegroundColor Gray
        $tcpConnections = Get-NetTCPConnection -ErrorAction Stop
        Write-Host "  Found $($tcpConnections.Count) TCP connections." -ForegroundColor Gray
        Write-Host "  Retrieving UDP endpoints..." -ForegroundColor Gray
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
        Write-Host "  Found $($udpEndpoints.Count) UDP endpoints." -ForegroundColor Gray
        
        $processCounter = 0
        $processesWithNetworkActivity = 0
        
        Write-Host "`n  Analyzing network connections for each process..." -ForegroundColor Cyan
        foreach ($process in $Processes) {
            $processCounter++
            if ($processCounter % 50 -eq 0 -or $processCounter -eq $Processes.Count) {
                Write-Host "  Progress: $processCounter of $($Processes.Count) processes analyzed." -ForegroundColor Gray
            }
            
            $processNetworkInfo = [PSCustomObject]@{
                ProcessId = $process.Id
                ProcessName = $process.Name
                TCP = @()
                UDP = @()
                HasNetworkActivity = $false
                SuspiciousConnections = @()
            }
            $processTcpConnections = $tcpConnections | Where-Object { $_.OwningProcess -eq $process.Id }
            
            if ($processTcpConnections.Count -gt 0) {
                $processesWithNetworkActivity++
            }
            
            foreach ($connection in $processTcpConnections) {
                $connectionCount++
                $isSuspicious = $false
                $suspiciousReasons = @()
                $unusualPorts = @(4444, 1337, 31337, 8080, 8888, 9999)
                if ($unusualPorts -contains $connection.RemotePort -or $unusualPorts -contains $connection.LocalPort) {
                    $isSuspicious = $true
                    $suspiciousReasons += "Unusual port number"
                }
                if ($connection.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|::1|fe80::)") {
                    if ($connection.RemotePort -notin @(80, 443, 53, 25, 587, 465, 993, 995, 143, 110, 21, 22)) {
                        $isSuspicious = $true
                        $suspiciousReasons += "External connection on non-standard port"
                    }
                }
                $connectionObj = [PSCustomObject]@{
                    LocalAddress = $connection.LocalAddress
                    LocalPort = $connection.LocalPort
                    RemoteAddress = $connection.RemoteAddress
                    RemotePort = $connection.RemotePort
                    State = $connection.State
                    CreationTime = $connection.CreationTime
                    IsSuspicious = $isSuspicious
                    SuspiciousReasons = $suspiciousReasons
                }
                
                if ($isSuspicious) {
                    $suspiciousConnectionCount++
                    $processNetworkInfo.SuspiciousConnections += $connectionObj
                    Write-Log -Message "Suspicious connection for process $($process.Name) (ID: $($process.Id)): $($connection.RemoteAddress):$($connection.RemotePort) - Reasons: $($suspiciousReasons -join '; ')" -Level "Warning"
                }
                
                $processNetworkInfo.TCP += $connectionObj
                $processNetworkInfo.HasNetworkActivity = $true
            }
            $processUdpEndpoints = $udpEndpoints | Where-Object { $_.OwningProcess -eq $process.Id }
            
            foreach ($endpoint in $processUdpEndpoints) {
                $endpointObj = [PSCustomObject]@{
                    LocalAddress = $endpoint.LocalAddress
                    LocalPort = $endpoint.LocalPort
                    CreationTime = $endpoint.CreationTime
                }
                
                $processNetworkInfo.UDP += $endpointObj
                $processNetworkInfo.HasNetworkActivity = $true
            }
            if ($processNetworkInfo.HasNetworkActivity) {
                $processNetwork += $processNetworkInfo
            }
        }
        
        Write-Host "`n  Found $processesWithNetworkActivity processes with network activity." -ForegroundColor Green
        Write-Host "  Identified $connectionCount total connections ($suspiciousConnectionCount suspicious)." -ForegroundColor Green
        Write-Log -Message "Collected network information for processes: $connectionCount TCP connections ($suspiciousConnectionCount suspicious)" -Level "Success"
        return $processNetwork
    }
    catch {
        Write-Log -Message "Error collecting process network information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting network information: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Build-ProcessTree {
    param ([array]$Processes)
    
    Write-Log -Message "Building process tree..." -Level "Info"
    Write-Host "  Building process relationship tree..." -ForegroundColor Cyan
    
    try {
        $processLookup = @{}
        foreach ($process in $Processes) {
            $processLookup[$process.Id] = $process
        }
        $childProcesses = @{}
        foreach ($process in $Processes) {
            $childProcesses[$process.Id] = @()
        }
        foreach ($process in $Processes) {
            if ($process.Parent -and $process.Parent.Id -gt 0) {
                $parentId = $process.Parent.Id
                if ($childProcesses.ContainsKey($parentId)) {
                    $childProcesses[$parentId] += $process.Id
                }
            }
        }
        $rootProcesses = $Processes | Where-Object { 
            $_.Parent -eq $null -or $_.Parent.Id -le 4 -or 
            ($_.Parent.Id -gt 0 -and -not $processLookup.ContainsKey($_.Parent.Id))
        }
        
        Write-Host "  Found $($rootProcesses.Count) root processes." -ForegroundColor Gray
        
        function Build-TreeNode {
            param (
                [int]$ProcessId,
                [int]$Depth = 0
            )
            
            $process = $processLookup[$ProcessId]
            
            $node = [PSCustomObject]@{
                Id = $process.Id
                Name = $process.Name
                Path = $process.Path
                CommandLine = $process.CommandLine
                Owner = $process.Owner
                StartTime = $process.StartTime
                Depth = $Depth
                Children = @()
                ChildCount = 0
                IsSuspicious = $process.IsSuspicious
                SuspiciousReasons = $process.SuspiciousReasons
            }
            if ($childProcesses.ContainsKey($ProcessId)) {
                foreach ($childId in $childProcesses[$ProcessId]) {
                    $childNode = Build-TreeNode -ProcessId $childId -Depth ($Depth + 1)
                    $node.Children += $childNode
                    $node.ChildCount += (1 + $childNode.ChildCount)
                }
            }
            
            return $node
        }
        $processTree = @()
        Write-Host "  Building tree structure..." -ForegroundColor Gray
        foreach ($rootProcess in $rootProcesses) {
            $treeNode = Build-TreeNode -ProcessId $rootProcess.Id
            $processTree += $treeNode
        }
        $suspiciousTree = @()
        foreach ($node in $processTree) {
            if ($node.IsSuspicious -or ($node.Children | Where-Object { $_.IsSuspicious })) {
                $suspiciousTree += $node
                Write-Log -Message "Suspicious process tree identified, root: $($node.Name) (ID: $($node.Id))" -Level "Warning"
            }
        }
        
        $treeResult = [PSCustomObject]@{
            FullTree = $processTree
            SuspiciousTreeRoots = $suspiciousTree
        }
        
        $suspiciousCount = $suspiciousTree.Count
        Write-Host "  Process tree built with $($rootProcesses.Count) root processes ($suspiciousCount suspicious trees)" -ForegroundColor Green
        Write-Log -Message "Process tree built successfully with $($rootProcesses.Count) root processes" -Level "Success"
        return $treeResult
    }
    catch {
        Write-Log -Message "Error building process tree: $($_.Exception.Message)" -Level "Error"
        Write-Host "  Error building process tree: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Main {
    Write-Host "`n========================= Process Collection Started =========================" -ForegroundColor Cyan
    Write-Host "Collection Time: $(Get-Date)" -ForegroundColor Cyan
    Write-Host "Computer Name: $ComputerName" -ForegroundColor Cyan
    Write-Host "Output Path: $OutputPath" -ForegroundColor Cyan
    Write-Host "Quick Scan Mode: $QuickScan" -ForegroundColor Cyan
    Write-Host "Collection Parameters:" -ForegroundColor Cyan
    Write-Host "  - Include Modules: $IncludeModules" -ForegroundColor Gray
    Write-Host "  - Include Handles: $IncludeHandles" -ForegroundColor Gray
    Write-Host "  - Include Command Line: $IncludeCommandLine" -ForegroundColor Gray
    Write-Host "  - Build Process Tree: $BuildProcessTree" -ForegroundColor Gray
    Write-Host "  - Filter System Processes: $FilterSystem" -ForegroundColor Gray
    Write-Host "=======================================================================" -ForegroundColor Cyan
    
    if (-not (Initialize-OutputLocation)) {
        Write-Error "Failed to initialize output location. Exiting."
        return
    }
    Write-Host "`n[1/5] Collecting Process Details" -ForegroundColor Yellow
    Write-Log -Message "Starting process collection..." -Level "Info"
    $processes = Get-ProcessDetails
    
    if ($processes.Count -eq 0) {
        Write-Log -Message "No processes collected. Exiting." -Level "Error"
        Write-Host "`nNo processes were collected. Exiting." -ForegroundColor Red
        return
    }
    Write-Host "Exporting process details to JSON..." -ForegroundColor Gray
    Export-ToJson -InputObject $processes -FilePath $ProcessesOutputPath
    if ($IncludeModules) {
        Write-Host "`n[2/5] Collecting Process Modules" -ForegroundColor Yellow
        $processModules = Get-ProcessModules -Processes $processes
        Write-Host "Exporting module information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $processModules -FilePath $ModulesOutputPath
    } else {
        Write-Host "`n[2/5] Skipping Process Modules Collection (Disabled)" -ForegroundColor DarkGray
    }
    if ($IncludeHandles) {
        Write-Host "`n[3/5] Collecting Process Handles" -ForegroundColor Yellow
        $processHandles = Get-ProcessHandles -Processes $processes
        Write-Host "Exporting handle information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $processHandles -FilePath $HandlesOutputPath
    } else {
        Write-Host "`n[3/5] Skipping Process Handles Collection (Disabled)" -ForegroundColor DarkGray
    }
    Write-Host "`n[4/5] Collecting Network Connections" -ForegroundColor Yellow
    $processNetwork = Get-ProcessNetwork -Processes $processes
    Write-Host "Exporting network information to JSON..." -ForegroundColor Gray
    Export-ToJson -InputObject $processNetwork -FilePath $NetworkOutputPath
    if ($BuildProcessTree) {
        Write-Host "`n[5/5] Building Process Tree" -ForegroundColor Yellow
        $processTree = Build-ProcessTree -Processes $processes
        Write-Host "Exporting process tree to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $processTree -FilePath $ProcessTreeOutputPath
    } else {
        Write-Host "`n[5/5] Skipping Process Tree Building (Disabled)" -ForegroundColor DarkGray
    }
    Write-Host "`nGenerating collection summary..." -ForegroundColor Cyan
    $summary = [PSCustomObject]@{
        CollectionTime = Get-Date
        ComputerName = $ComputerName
        TotalProcesses = $processes.Count
        SuspiciousProcesses = ($processes | Where-Object { $_.IsSuspicious }).Count
        NetworkActiveProcesses = $processNetwork.Count
        CommandLineAvailable = $IncludeCommandLine
        ModulesCollected = $IncludeModules
        HandlesCollected = $IncludeHandles
        ProcessTreeBuilt = $BuildProcessTree
        SystemProcessesFiltered = $FilterSystem
    }
    
    Export-ToJson -InputObject $summary -FilePath $SummaryOutputPath
    Write-Host "`n========================= Collection Summary =========================" -ForegroundColor Green
    Write-Host "Total Processes: $($processes.Count)" -ForegroundColor White
    Write-Host "Suspicious Processes: $(($processes | Where-Object { $_.IsSuspicious }).Count)" -ForegroundColor White
    Write-Host "Processes with Network Activity: $($processNetwork.Count)" -ForegroundColor White
    Write-Host "Results saved to: $OutputPath" -ForegroundColor White
    Write-Host "===================================================================" -ForegroundColor Green
    
    Write-Log -Message "Process collection completed successfully" -Level "Success"
    Write-Log -Message "Results saved to $OutputPath" -Level "Success"
}

Main

# AutorunsCollector.ps1
# Author: yasser.magdy102030@gmail.com
# Part of Compromise Assessment Framework
# Purpose: Collects different artifacts from Windows systems to identify persistence mechanisms (autoruns, services, scheduled tasks,Startup Folders, WMI Persistence and User-Login Scripts)


$ScriptVersion = "1.0"
$CollectionTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ComputerName = $env:COMPUTERNAME
$OutputPath = "$PSScriptRoot\ForensicOutput\$ComputerName\Autoruns_$CollectionTimestamp"


function Initialize-OutputLocation {
    if (!(Test-Path -Path $OutputPath)) {
        try {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Host "[+] Created output directory: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Error creating output directory: $($_.Exception.Message)" -ForegroundColor Red
            exit
        }
    }
}


function Write-CollectionResult {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DataType,
        
        [Parameter(Mandatory = $true)]
        [object]$Data
    )
    
    $FilePath = "$OutputPath\${DataType}_$CollectionTimestamp.json"
    
    try {
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8
        Write-Host "[+] Collected $DataType data saved to: $FilePath" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error saving $DataType data: $($_.Exception.Message)" -ForegroundColor Red
    }
}


function Get-FileHash256 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    if (Test-Path -Path $FilePath -PathType Leaf) {
        try {
            $Hash = Get-FileHash -Path $FilePath -Algorithm SHA256
            return $Hash.Hash
        }
        catch {
            return "Error calculating hash: $($_.Exception.Message)"
        }
    }
    else {
        return "File not found"
    }
}


function Show-Banner {
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host "      AUTORUN ARTIFACTS COLLECTOR v$ScriptVersion" -ForegroundColor Yellow
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host "Computer: $ComputerName" -ForegroundColor Cyan
    Write-Host "Started: $CollectionTimestamp" -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host ""
}


function Get-ScheduledTaskInfo {
    Write-Host "[*] Collecting Scheduled Tasks..." -ForegroundColor Yellow
    
    try {
        $Tasks = Get-ScheduledTask | ForEach-Object {
            $TaskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
            
            
            $TaskActions = @($_.Actions)
            $ProcessedActions = $TaskActions | ForEach-Object {
                $Action = $_
                
                $ExecutablePath = if ($Action.Execute -is [string] -and ![string]::IsNullOrEmpty($Action.Execute)) { 
                    $Action.Execute 
                } else { 
                    "N/A" 
                }
                
                $Arguments = if ($Action.Arguments -is [string]) { 
                    $Action.Arguments 
                } else { 
                    "N/A" 
                }
                
                $ExecutableHash = "N/A"
                if ($ExecutablePath -ne "N/A" -and (Test-Path -Path $ExecutablePath -PathType Leaf -ErrorAction SilentlyContinue)) {
                    $ExecutableHash = Get-FileHash256 -FilePath $ExecutablePath
                }
                
                
                [PSCustomObject]@{
                    Type = $Action.GetType().Name
                    ExecutablePath = $ExecutablePath
                    Arguments = $Arguments
                    ExecutableHash = $ExecutableHash
                    WorkingDirectory = $Action.WorkingDirectory
                }
            }
            
            
            [PSCustomObject]@{
                TaskName = $_.TaskName
                TaskPath = $_.TaskPath
                State = $_.State
                Description = $_.Description
                Author = $_.Author
                Actions = $ProcessedActions
                LastRunTime = $TaskInfo.LastRunTime
                NextRunTime = $TaskInfo.NextRunTime
                LastTaskResult = $TaskInfo.LastTaskResult
                Triggers = $_.Triggers | ForEach-Object {
                    [PSCustomObject]@{
                        TriggerType = $_.CimClass.CimClassName
                        Enabled = $_.Enabled
                        StartBoundary = $_.StartBoundary
                        EndBoundary = $_.EndBoundary
                        ExecutionTimeLimit = $_.ExecutionTimeLimit
                    }
                }
            }
        }
        
        Write-CollectionResult -DataType "ScheduledTasks" -Data $Tasks
        return $Tasks
    }
    catch {
        Write-Host "[-] Error collecting Scheduled Tasks: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-ServicesInfo {
    Write-Host "[*] Collecting Services..." -ForegroundColor Yellow
    
    try {
        $Services = Get-WmiObject -Class Win32_Service | ForEach-Object {
            $ServicePath = $_.PathName
            $ServiceExecutable = "N/A"
            $ExecutableHash = "N/A"
            
            if (-not [string]::IsNullOrWhiteSpace($ServicePath)) {
                if ($ServicePath -match '^"([^"]+)"') {
                    $ServiceExecutable = $Matches[1]
                }
                elseif ($ServicePath -match '^(\S+)') {
                    $ServiceExecutable = $Matches[1]
                }
                else {
                    $ServiceExecutable = $ServicePath
                }
                
                if (-not [string]::IsNullOrWhiteSpace($ServiceExecutable) -and 
                    (Test-Path -Path $ServiceExecutable -PathType Leaf -ErrorAction SilentlyContinue)) {
                    try {
                        $ExecutableHash = Get-FileHash256 -FilePath $ServiceExecutable
                    }
                    catch {
                        $ExecutableHash = "Error: $($_.Exception.Message)"
                    }
                }
            }
            
            $IsSvchost = $false
            if ($ServicePath -like "*\svchost.exe*") {
                $IsSvchost = $true
                try {
                    $ServiceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)\Parameters"
                    if (Test-Path $ServiceRegPath) {
                        $ServiceDLL = (Get-ItemProperty -Path $ServiceRegPath -ErrorAction SilentlyContinue).ServiceDll
                        if (-not [string]::IsNullOrWhiteSpace($ServiceDLL) -and 
                            (Test-Path -Path $ServiceDLL -PathType Leaf -ErrorAction SilentlyContinue)) {
                            $ExecutableHash = Get-FileHash256 -FilePath $ServiceDLL
                        }
                    }
                }
                catch {
                }
            }
            
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Description = $_.Description
                StartMode = $_.StartMode
                State = $_.State
                Status = $_.Status
                PathName = $ServicePath
                ExecutablePath = $ServiceExecutable
                IsSvchost = $IsSvchost
                ExecutableHash = $ExecutableHash
                StartName = $_.StartName
                ProcessId = $_.ProcessId
                CreationDate = $_.CreationClassName
            }
        }
        
        Write-CollectionResult -DataType "Services" -Data $Services
        return $Services
    }
    catch {
        Write-Host "[-] Error collecting Services: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-RegistryAutoruns {
    Write-Host "[*] Collecting Registry Autoruns..." -ForegroundColor Yellow
    
    $AutorunLocations = @{
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" = "HKLM Run"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" = "HKLM RunOnce"
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" = "HKLM Run (32-bit)"
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" = "HKLM RunOnce (32-bit)"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" = "HKCU Run"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" = "HKCU RunOnce"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" = "HKLM Startup Approved"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" = "HKLM Startup Approved (32-bit)"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" = "HKLM Startup Folder Approved"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" = "HKCU Startup Approved"
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" = "HKCU Startup Folder Approved"
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" = "Winlogon Userinit"
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" = "Winlogon Shell"
        "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load" = "HKCU Windows Load"
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs" = "AppInit DLLs"
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute" = "Boot Execute"
    }
    
    $AutorunEntries = @()
    
    foreach ($Location in $AutorunLocations.Keys) {
        $LocationName = $AutorunLocations[$Location]
        try {
            if (Test-Path -Path $Location) {
                $Values = Get-ItemProperty -Path $Location -ErrorAction SilentlyContinue
                
                $Properties = $Values.PSObject.Properties | Where-Object { 
                    $_.Name -notmatch 'PSPath|PSParentPath|PSChildName|PSProvider|PSDrive'
                }
                
                foreach ($Property in $Properties) {
                    $Value = $Property.Value
                    
                    $ExecutablePath = $null
                    if ($Value -match '^"([^"]+)"') {
                        $ExecutablePath = $Matches[1]
                    }
                    elseif ($Value -match '^(\S+)') {
                        $ExecutablePath = $Matches[1]
                    }
                    
                    $AutorunEntries += [PSCustomObject]@{
                        Source = $LocationName
                        KeyPath = $Location
                        EntryName = $Property.Name
                        Command = $Value
                        ExecutablePath = $ExecutablePath
                        ExecutableHash = if ($ExecutablePath) { Get-FileHash256 -FilePath $ExecutablePath } else { "N/A" }
                    }
                }
            }
        }
        catch {
            Write-Host "[-] Error accessing $Location : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-CollectionResult -DataType "RegistryAutoruns" -Data $AutorunEntries
    return $AutorunEntries
}

function Get-StartupFolders {
    Write-Host "[*] Collecting Startup Folders..." -ForegroundColor Yellow
    
    $StartupLocations = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    $StartupFiles = @()
    
    foreach ($Location in $StartupLocations) {
        try {
            if (Test-Path -Path $Location) {
                $Files = Get-ChildItem -Path $Location -Recurse -File -ErrorAction SilentlyContinue
                
                foreach ($File in $Files) {
                    $LinkTarget = $null
                    $RealExecutable = $null
                    $RealExecutableHash = "N/A"
                    
                    if ($File.Extension -eq ".lnk") {
                        try {
                            $Shell = New-Object -ComObject WScript.Shell
                            $Shortcut = $Shell.CreateShortcut($File.FullName)
                            $LinkTarget = $Shortcut.TargetPath
                            $Arguments = $Shortcut.Arguments
                            
                            if (Test-Path -Path $LinkTarget -PathType Leaf) {
                                $RealExecutable = $LinkTarget
                                $RealExecutableHash = Get-FileHash256 -FilePath $LinkTarget
                            }
                        }
                        catch {
                            $LinkTarget = "Error processing shortcut: $($_.Exception.Message)"
                        }
                    }
                    else {
                        $RealExecutable = $File.FullName
                        $RealExecutableHash = Get-FileHash256 -FilePath $File.FullName
                    }
                    
                    $StartupFiles += [PSCustomObject]@{
                        FolderPath = $Location
                        FileName = $File.Name
                        Extension = $File.Extension
                        CreationTime = $File.CreationTime
                        LastWriteTime = $File.LastWriteTime
                        LastAccessTime = $File.LastAccessTime
                        FileSize = $File.Length
                        FileHash = Get-FileHash256 -FilePath $File.FullName
                        IsLink = ($File.Extension -eq ".lnk")
                        LinkTarget = $LinkTarget
                        LinkArguments = if ($File.Extension -eq ".lnk") { $Arguments } else { $null }
                        TargetExecutable = $RealExecutable
                        TargetExecutableHash = $RealExecutableHash
                    }
                }
            }
        }
        catch {
            Write-Host "[-] Error accessing $Location : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-CollectionResult -DataType "StartupFolders" -Data $StartupFiles
    return $StartupFiles
}


function Get-WMIPersistence {
    Write-Host "[*] Collecting WMI Persistence mechanisms..." -ForegroundColor Yellow
    
    try {

        $WMIEventFilters = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                EventNamespace = $_.EventNamespace
                QueryLanguage = $_.QueryLanguage
                Query = $_.Query
                CreatorSID = (New-Object System.Security.Principal.SecurityIdentifier($_.CreatorSID, 0)).Value
            }
        }
        
        $WMIEventConsumers = Get-WmiObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
            $ConsumerType = $_.PSObject.TypeNames[0].Split(".")[-1]
            
            $Properties = @{
                Name = $_.Name
                ConsumerType = $ConsumerType
                CreatorSID = (New-Object System.Security.Principal.SecurityIdentifier($_.CreatorSID, 0)).Value
            }
            
            switch ($ConsumerType) {
                "CommandLineEventConsumer" {
                    $Properties["ExecutablePath"] = $_.ExecutablePath
                    $Properties["CommandLineTemplate"] = $_.CommandLineTemplate
                    if ($_.ExecutablePath) {
                        $Properties["ExecutableHash"] = Get-FileHash256 -FilePath $_.ExecutablePath
                    }
                }
                "ActiveScriptEventConsumer" {
                    $Properties["ScriptingEngine"] = $_.ScriptingEngine
                    $Properties["ScriptText"] = $_.ScriptText
                }
                "LogFileEventConsumer" {
                    $Properties["LogFileName"] = $_.LogFileName
                    $Properties["Text"] = $_.Text
                }
            }
            
            [PSCustomObject]$Properties
        }
        
        $WMIBindings = Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Filter = $_.Filter.Split("=")[-1].Replace('"', '').Trim()
                Consumer = $_.Consumer.Split("=")[-1].Replace('"', '').Trim()
                CreatorSID = (New-Object System.Security.Principal.SecurityIdentifier($_.CreatorSID, 0)).Value
            }
        }
        
        $WMIData = [PSCustomObject]@{
            EventFilters = $WMIEventFilters
            EventConsumers = $WMIEventConsumers
            FilterToConsumerBindings = $WMIBindings
        }
        
        Write-CollectionResult -DataType "WMIPersistence" -Data $WMIData
        return $WMIData
    }
    catch {
        Write-Host "[-] Error collecting WMI persistence: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-UserLoginScripts {
    Write-Host "[*] Collecting User Login Scripts..." -ForegroundColor Yellow
    
    try {
        $GPOScripts = @()
        $GPOPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff"
        )
        
        foreach ($Path in $GPOPaths) {
            if (Test-Path $Path) {
                $GPOKeys = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
                foreach ($Key in $GPOKeys) {
                    $ScriptKeys = Get-ChildItem -Path $Key.PSPath -ErrorAction SilentlyContinue
                    foreach ($ScriptKey in $ScriptKeys) {
                        $Script = Get-ItemProperty -Path $ScriptKey.PSPath -ErrorAction SilentlyContinue
                        if ($Script -and $Script.Script) {
                            $ScriptPath = $Script.Script
                            $GPOScripts += [PSCustomObject]@{
                                Type = $Path.Split('\')[-1]
                                GPO = $Key.PSChildName
                                ScriptOrder = $ScriptKey.PSChildName
                                ScriptPath = $ScriptPath
                                Parameters = $Script.Parameters
                                ScriptHash = Get-FileHash256 -FilePath $ScriptPath
                            }
                        }
                    }
                }
            }
        }
        

        $UserScripts = Get-WmiObject -Class Win32_UserProfile | ForEach-Object {
            try {
                $SID = $_.SID
                $UserName = ([System.Security.Principal.SecurityIdentifier]$SID).Translate([System.Security.Principal.NTAccount]).Value
                

                $UserRegPath = "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                if (Test-Path $UserRegPath) {
                    $LoginScript = (Get-ItemProperty -Path $UserRegPath -ErrorAction SilentlyContinue).LogonScript
                    
                    if ($LoginScript) {
                        [PSCustomObject]@{
                            UserName = $UserName
                            SID = $SID
                            LoginScript = $LoginScript
                            ScriptHash = Get-FileHash256 -FilePath $LoginScript
                        }
                    }
                }
            }
            catch {
            }
        }
        
        $LoginScriptData = [PSCustomObject]@{
            GPOScripts = $GPOScripts
            UserLoginScripts = $UserScripts
        }
        
        Write-CollectionResult -DataType "LoginScripts" -Data $LoginScriptData
        return $LoginScriptData
    }
    catch {
        Write-Host "[-] Error collecting Login Scripts: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Start-AutorunsCollection {
    Show-Banner
    Initialize-OutputLocation
    
    $SystemInfo = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OSVersion = [System.Environment]::OSVersion.VersionString
        Architecture = $env:PROCESSOR_ARCHITECTURE
        CurrentUser = $env:USERNAME
        Domain = $env:USERDOMAIN
        CollectionDate = $CollectionTimestamp
    }
    
    Write-CollectionResult -DataType "SystemInfo" -Data $SystemInfo
    

    $ScheduledTasks = Get-ScheduledTaskInfo
    $Services = Get-ServicesInfo
    $RegistryAutoruns = Get-RegistryAutoruns
    $StartupFolders = Get-StartupFolders
    $WMIPersistence = Get-WMIPersistence
    $LoginScripts = Get-UserLoginScripts
    $GPOScriptsCount = if ($LoginScripts -and $LoginScripts.GPOScripts) { $LoginScripts.GPOScripts.Count } else { 0 }
    $UserLoginScriptsCount = if ($LoginScripts -and $LoginScripts.UserLoginScripts) { $LoginScripts.UserLoginScripts.Count } else { 0 }
    $TotalLoginScriptsCount = $GPOScriptsCount + $UserLoginScriptsCount
    

    $Summary = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CollectionDate = $CollectionTimestamp
        ScheduledTasksCount = if ($ScheduledTasks) { $ScheduledTasks.Count } else { 0 }
        ServicesCount = if ($Services) { $Services.Count } else { 0 }
        RegistryAutorunsCount = if ($RegistryAutoruns) { $RegistryAutoruns.Count } else { 0 }
        StartupFoldersCount = if ($StartupFolders) { $StartupFolders.Count } else { 0 }
        WMIPersistenceBindingsCount = if ($WMIPersistence -and $WMIPersistence.FilterToConsumerBindings) { $WMIPersistence.FilterToConsumerBindings.Count } else { 0 }
        LoginScriptsCount = $TotalLoginScriptsCount
    }
    
    Write-CollectionResult -DataType "Summary" -Data $Summary
    

    $LogPath = "$OutputPath\collection_log.txt"
    $LogContent = @"
====================================
Autoruns Collection Log
====================================
Computer: $($env:COMPUTERNAME)
Collection Time: $CollectionTimestamp
Collection Path: $OutputPath

Items Collected:
- Scheduled Tasks: $($Summary.ScheduledTasksCount)
- Services: $($Summary.ServicesCount)
- Registry Autoruns: $($Summary.RegistryAutorunsCount)
- Startup Folders: $($Summary.StartupFoldersCount)
- WMI Persistence: $($Summary.WMIPersistenceBindingsCount)
- Login Scripts: $($Summary.LoginScriptsCount)
====================================
"@
    
    $LogContent | Out-File -FilePath $LogPath -Encoding utf8
    
    Write-Host ""
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host "      AUTORUN COLLECTION COMPLETED" -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host "Output saved to: $OutputPath" -ForegroundColor Cyan
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "- Scheduled Tasks: $($Summary.ScheduledTasksCount)" -ForegroundColor White
    Write-Host "- Services: $($Summary.ServicesCount)" -ForegroundColor White
    Write-Host "- Registry Autoruns: $($Summary.RegistryAutorunsCount)" -ForegroundColor White
    Write-Host "- Startup Folders: $($Summary.StartupFoldersCount)" -ForegroundColor White
    Write-Host "- WMI Persistence: $($Summary.WMIPersistenceBindingsCount)" -ForegroundColor White
    Write-Host "- Login Scripts: $($Summary.LoginScriptsCount)" -ForegroundColor White
    Write-Host "====================================================" -ForegroundColor Cyan
}

Start-AutorunsCollection
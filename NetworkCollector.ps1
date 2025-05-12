#requires -Version 5.1
<#
.SYNOPSIS
    Advanced network information collector for compromise assessment.

.DESCRIPTION
    Part of the PowerShell Compromise Assessment Framework - PSCAF.
    Collects comprehensive network information including interfaces, connections,
    firewall configuration, wireless settings, services, and event logs.
    Performs security analysis to identify potential compromise indicators.

.PARAMETER OutputPath
    Path where the collected artifacts will be stored.

.PARAMETER QuickScan
    Performs a quick scan by focusing only on critical network components
    and limiting the depth of collection.

.PARAMETER ComputerName
    Target computer name. Defaults to the local computer.

.PARAMETER ModuleFlags
    Controls which collection function to run. 
    Valid values: All, Interfaces, Connections, Routing, DNS, Shares, 
    Firewall, Wireless, Services, EventLogs, Security
    Default: "All"

.EXAMPLE
    .\NetworkCollector.ps1 -OutputPath "C:\Compromise_Assessment\Network_Artifacts" -QuickScan

.EXAMPLE
    .\NetworkCollector.ps1 -OutputPath "C:\Compromise_Assessment\Network_Artifacts" -ModuleFlags Interfaces,Connections,Firewall

.NOTES
    This is an advanced network collector that gathers detailed information
    about network configuration and performs security analysis to identify
    potential compromise indicators or security vulnerabilities.

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
    [ValidateSet("All", "Interfaces", "Connections", "Routing", "DNS", "Shares", "Firewall", "Wireless", "Services", "EventLogs", "Security")]
    [string[]]$ModuleFlags = @("All"),
    
    [Parameter(Mandatory = $false)]
    [hashtable]$FilterOptions = @{}
)


$CollectionTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFilePath = Join-Path -Path $OutputPath -ChildPath "NetworkCollection_Log_$CollectionTimestamp.log"
$InterfacesOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkInterfaces_$CollectionTimestamp.json"
$ConnectionsOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkConnections_$CollectionTimestamp.json"
$RoutingOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkRoutes_$CollectionTimestamp.json"
$DNSCacheOutputPath = Join-Path -Path $OutputPath -ChildPath "DNSCache_$CollectionTimestamp.json"
$NetworkSharesOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkShares_$CollectionTimestamp.json"
$FirewallOutputPath = Join-Path -Path $OutputPath -ChildPath "FirewallConfiguration_$CollectionTimestamp.json"
$WirelessOutputPath = Join-Path -Path $OutputPath -ChildPath "WirelessNetworks_$CollectionTimestamp.json"
$NetworkServicesOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkServices_$CollectionTimestamp.json"
$EventLogsOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkEventLogs_$CollectionTimestamp.json"
$SecurityAnalysisOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkSecurityAnalysis_$CollectionTimestamp.json"
$SummaryOutputPath = Join-Path -Path $OutputPath -ChildPath "Summary_$CollectionTimestamp.json"
$CollectionTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFilePath = Join-Path -Path $OutputPath -ChildPath "NetworkCollection_Log_$CollectionTimestamp.log"
$InterfacesOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkInterfaces_$CollectionTimestamp.json"
$ConnectionsOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkConnections_$CollectionTimestamp.json"
$RoutingOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkRoutes_$CollectionTimestamp.json"
$DNSCacheOutputPath = Join-Path -Path $OutputPath -ChildPath "DNSCache_$CollectionTimestamp.json"
$NetworkSharesOutputPath = Join-Path -Path $OutputPath -ChildPath "NetworkShares_$CollectionTimestamp.json"
$SummaryOutputPath = Join-Path -Path $OutputPath -ChildPath "Summary_$CollectionTimestamp.json"


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

function Export-ToJson {
    param (
        [Parameter(Mandatory = $true)]
        [object]$InputObject,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $InputObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $FilePath -Encoding UTF8
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
Network Collection Module (Simple)
Started: $(Get-Date)
Computer: $ComputerName
=================================================
"@
        $headerText | Out-File -FilePath $LogFilePath -Encoding UTF8
        
        Write-Log -Message "Network collection initialized" -Level "Info"
        return $true
    }
    catch {
        Write-Warning "Failed to initialize output location: $($_.Exception.Message)"
        return $false
    }
}

function Test-AdminPrivileges {
   
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Get-NetworkInterfaces {
    Write-Log -Message "Collecting network interface information..." -Level "Info"
    Write-Host "Collecting network interface information..." -ForegroundColor Cyan
    
    try {
        
        $adapters = Get-NetAdapter -ErrorAction Stop
        Write-Host "  Found $($adapters.Count) network adapters." -ForegroundColor Gray
        
        $interfaces = @()
        foreach ($adapter in $adapters) {
            try {
                
                $ipAddresses = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
                
                
                $ipv4 = ($ipAddresses | Where-Object { $_.AddressFamily -eq "IPv4" } | Select-Object -ExpandProperty IPAddress) -join ", "
                $ipv6 = ($ipAddresses | Where-Object { $_.AddressFamily -eq "IPv6" } | Select-Object -ExpandProperty IPAddress) -join ", "
                
                
                $adapterInfo = [PSCustomObject]@{
                    Name = $adapter.Name
                    Description = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    MacAddress = $adapter.MacAddress
                    Speed = "$($adapter.LinkSpeed)"
                    IPv4Address = $ipv4
                    IPv6Address = $ipv6
                }
                
                $interfaces += $adapterInfo
            }
            catch {
                Write-Log -Message "Error processing adapter $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        Write-Host "  Successfully collected information on $($interfaces.Count) network interfaces." -ForegroundColor Green
        Write-Log -Message "Successfully collected information on $($interfaces.Count) network interfaces." -Level "Success"
        return $interfaces
    }
    catch {
        Write-Log -Message "Error collecting network interface information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting network interface information: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

function Get-NetworkConnections {
    Write-Log -Message "Collecting network connection information..." -Level "Info"
    Write-Host "Collecting network connection information..." -ForegroundColor Cyan
    
    try {
        
        $tcpConnections = Get-NetTCPConnection -ErrorAction Stop
        Write-Host "  Found $($tcpConnections.Count) TCP connections." -ForegroundColor Gray
        
        
        $connections = @()
        foreach ($connection in $tcpConnections) {
            try {
                
                $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.Name } else { "Unknown" }
                
                
                $connectionObj = [PSCustomObject]@{
                    LocalAddress = $connection.LocalAddress
                    LocalPort = $connection.LocalPort
                    RemoteAddress = $connection.RemoteAddress
                    RemotePort = $connection.RemotePort
                    State = $connection.State
                    ProcessId = $connection.OwningProcess
                    ProcessName = $processName
                }
                
                $connections += $connectionObj
            }
            catch {
                Write-Log -Message "Error processing connection: $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        
        $listeners = $tcpConnections | Where-Object { $_.State -eq "Listen" }
        $listenerSummary = $listeners | Group-Object -Property LocalPort | ForEach-Object {
            [PSCustomObject]@{
                Port = $_.Name
                Count = $_.Count
                Processes = ($_.Group | ForEach-Object { 
                    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc) { $proc.Name } else { "Unknown" }
                } | Select-Object -Unique) -join ", "
            }
        }
        
        $result = [PSCustomObject]@{
            Connections = $connections
            ListenerSummary = $listenerSummary
            TotalConnections = $connections.Count
            TotalListeners = $listeners.Count
        }
        
        Write-Host "  Found $($connections.Count) total connections." -ForegroundColor Green
        Write-Log -Message "Collected network connection information: $($connections.Count) connections." -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error collecting network connection information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting network connection information: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-RoutingInformation {
    Write-Log -Message "Collecting routing information..." -Level "Info"
    Write-Host "Collecting routing information..." -ForegroundColor Cyan
    
    try {
        
        Write-Host "  Retrieving routing table..." -ForegroundColor Gray
        $routes = Get-NetRoute -ErrorAction Stop
        
        
        $routeInfo = @()
        foreach ($route in $routes) {
            $routeObj = [PSCustomObject]@{
                DestinationPrefix = $route.DestinationPrefix
                NextHop = $route.NextHop
                InterfaceIndex = $route.InterfaceIndex
                InterfaceAlias = $route.InterfaceAlias
                RouteMetric = $route.RouteMetric
                Protocol = $route.Protocol
                AddressFamily = $route.AddressFamily
            }
            
            $routeInfo += $routeObj
        }
        
        
        Write-Host "  Retrieving ARP table..." -ForegroundColor Gray
        $arpEntries = @()
        try {
            $arpOutput = & arp -a
            
            
            $arpPattern = "\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]+)\s+(\w+)"
            foreach ($line in $arpOutput) {
                if ($line -match $arpPattern) {
                    $ipAddress = $Matches[1]
                    $macAddress = $Matches[2]
                    $type = $Matches[3]
                    
                    $arpEntries += [PSCustomObject]@{
                        IPAddress = $ipAddress
                        MACAddress = $macAddress
                        Type = $type
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Error collecting ARP table: $($_.Exception.Message)" -Level "Warning"
        }
        
        $result = [PSCustomObject]@{
            Routes = $routeInfo
            ARPEntries = $arpEntries
            RouteCount = $routes.Count
        }
        
        Write-Host "  Found $($routes.Count) routes and $($arpEntries.Count) ARP entries." -ForegroundColor Green
        Write-Log -Message "Collected routing information: $($routes.Count) routes." -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error collecting routing information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting routing information: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-DNSCacheInformation {
    Write-Log -Message "Collecting DNS cache information..." -Level "Info"
    Write-Host "Collecting DNS cache information..." -ForegroundColor Cyan
    
    try {
        
        Write-Host "  Retrieving DNS client cache..." -ForegroundColor Gray
        $dnsCache = Get-DnsClientCache -ErrorAction Stop
        
        
        $cacheEntries = @()
        foreach ($entry in $dnsCache) {
            $cacheObj = [PSCustomObject]@{
                Entry = $entry.Entry
                Name = $entry.Name
                Data = $entry.Data
                Type = $entry.Type
                TimeToLive = $entry.TimeToLive
                Section = $entry.Section
            }
            
            $cacheEntries += $cacheObj
        }
        
        
        $hostsFile = @()
        try {
            $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
            if (Test-Path $hostsPath) {
                $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
                
                foreach ($line in $hostsContent) {
                    $line = $line.Trim()
                    
                    
                    if ($line -match "^\s*#" -or [string]::IsNullOrWhiteSpace($line)) {
                        continue
                    }
                    
                    
                    if ($line -match "^\s*(\S+)\s+(.+)$") {
                        $ip = $Matches[1]
                        $hostnames = $Matches[2] -split "\s+"
                        
                        $entry = [PSCustomObject]@{
                            IPAddress = $ip
                            Hostnames = $hostnames
                            Line = $line
                        }
                        
                        $hostsFile += $entry
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Error reading hosts file: $($_.Exception.Message)" -Level "Warning"
        }
        
        $result = [PSCustomObject]@{
            CacheEntries = $cacheEntries
            HostsFileEntries = $hostsFile
            TotalCacheEntries = $cacheEntries.Count
            TotalHostsEntries = $hostsFile.Count
        }
        
        Write-Host "  Found $($cacheEntries.Count) DNS cache entries and $($hostsFile.Count) hosts file entries." -ForegroundColor Green
        Write-Log -Message "Collected DNS cache information: $($cacheEntries.Count) entries." -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error collecting DNS cache information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting DNS cache information: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-NetworkShareInformation {
    Write-Log -Message "Collecting network share information..." -Level "Info"
    Write-Host "Collecting network share information..." -ForegroundColor Cyan
    
    try {
        
        Write-Host "  Retrieving local shared folders..." -ForegroundColor Gray
        $shares = Get-SmbShare -ErrorAction Stop
        
        
        $shareInfo = @()
        foreach ($share in $shares) {
            try {
                
                $permissions = @()
                try {
                    $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                    foreach ($ace in $acl) {
                        $permissions += [PSCustomObject]@{
                            AccountName = $ace.AccountName
                            AccessRight = $ace.AccessRight
                            AccessControlType = $ace.AccessControlType
                        }
                    }
                }
                catch {
                    write-host "Unable to get permissions"
                }
                
                
                $shareObj = [PSCustomObject]@{
                    Name = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    ShareType = $share.ShareType
                    Special = $share.Special
                    CurrentUsers = $share.CurrentUsers
                    Permissions = $permissions
                    IsSystemShare = $share.Name -match "\$$"
                    IsHidden = $share.Name.EndsWith("$")
                }
                
                $shareInfo += $shareObj
            }
            catch {
                Write-Log -Message "Error processing share $($share.Name): $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        
        $connectedDrives = @()
        try {
            $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.DisplayRoot -match "\\\\" }
            foreach ($drive in $drives) {
                $connectedDrives += [PSCustomObject]@{
                    Name = $drive.Name
                    Root = $drive.Root
                    DisplayRoot = $drive.DisplayRoot
                    Used = if ($drive.Used) { $drive.Used } else { 0 }
                    Free = if ($drive.Free) { $drive.Free } else { 0 }
                }
            }
        }
        catch {
            Write-Log -Message "Error getting connected drives: $($_.Exception.Message)" -Level "Warning"
        }
        
        $result = [PSCustomObject]@{
            LocalShares = $shareInfo
            ConnectedDrives = $connectedDrives
            TotalShares = $shareInfo.Count
            TotalConnectedDrives = $connectedDrives.Count
            NonSystemShares = ($shareInfo | Where-Object { -not $_.IsSystemShare }).Count
        }
        
        Write-Host "  Found $($shareInfo.Count) local shares and $($connectedDrives.Count) connected drives." -ForegroundColor Green
        Write-Log -Message "Collected network share information: $($shareInfo.Count) shares, $($connectedDrives.Count) connected drives." -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error collecting network share information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting network share information: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-FirewallConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$QuickScan
    )
    
    Write-Log -Message "Collecting firewall configuration information..." -Level "Info"
    Write-Host "Collecting firewall configuration information..." -ForegroundColor Cyan
    
    try {
        
        $firewallProfiles = @()
        $firewallRules = @()
        $suspiciousRules = @()
        
        #firewall profiles (Domain, Private, Public)
        Write-Host "  Retrieving firewall profiles..." -ForegroundColor Gray
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        
        foreach ($profile in $profiles) {
            $profileObj = [PSCustomObject]@{
                Name = $profile.Name
                Enabled = $profile.Enabled
                DefaultInboundAction = $profile.DefaultInboundAction
                DefaultOutboundAction = $profile.DefaultOutboundAction
                AllowInboundRules = $profile.AllowInboundRules
                AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
                AllowLocalIPsecRules = $profile.AllowLocalIPsecRules
                AllowUserApps = $profile.AllowUserApps
                AllowUserPorts = $profile.AllowUserPorts
                NotifyOnListen = $profile.NotifyOnListen
                EnableStealthModeForIPsec = $profile.EnableStealthModeForIPsec
                LogFileName = $profile.LogFileName
                LogMaxSizeKilobytes = $profile.LogMaxSizeKilobytes
                LogAllowed = $profile.LogAllowed
                LogBlocked = $profile.LogBlocked
                LogIgnored = $profile.LogIgnored
                DisabledInterfaceAliases = $profile.DisabledInterfaceAliases
            }
            
            $firewallProfiles += $profileObj
        }
        
        #firewall rules(QuickScan will limit it)
        Write-Host "  Retrieving firewall rules..." -ForegroundColor Gray
        
        
        if ($QuickScan) {
            
            $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop |
                     Select-Object -First 500
            Write-Log -Message "QuickScan enabled - collected only enabled inbound allow rules (limited to 500 rules)" -Level "Info"
        } else {
            $rules = Get-NetFirewallRule -ErrorAction Stop
            Write-Log -Message "Full scan - collected all firewall rules" -Level "Info"
        }
        
        
        $total = $rules.Count
        $i = 0
        
        foreach ($rule in $rules) {
            $i++
            if ($i % 100 -eq 0) {
                Write-Host "    Processing rule $i of $total..." -ForegroundColor Gray
            }
            
            try {
               
                $addresses = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $ports = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $apps = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                $services = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                
                
                $ruleObj = [PSCustomObject]@{
                    Name = $rule.Name
                    DisplayName = $rule.DisplayName
                    Description = $rule.Description
                    DisplayGroup = $rule.DisplayGroup
                    Enabled = $rule.Enabled
                    Direction = $rule.Direction
                    Action = $rule.Action
                    EdgeTraversalPolicy = $rule.EdgeTraversalPolicy
                    Profile = $rule.Profile
                    LocalAddresses = $addresses.LocalAddress -join ", "
                    RemoteAddresses = $addresses.RemoteAddress -join ", "
                    LocalPorts = $ports.LocalPort -join ", "
                    RemotePorts = $ports.RemotePort -join ", "
                    Protocol = $ports.Protocol
                    IcmpType = $ports.IcmpType
                    Program = $apps.Program
                    Package = $apps.Package
                    Service = $services.Service
                }
                
                $firewallRules += $ruleObj
                
                
                $isSuspicious = $false
                $suspiciousReasons = @()
                
                
                if ($rule.Direction -eq "Inbound" -and $rule.Action -eq "Allow") {
                    
                    $sensitivePorts = @('22', '23', '3389', '445', '135', '139', '5985', '5986')
                    $rulePorts = $ports.LocalPort
                    
                    foreach ($port in $sensitivePorts) {
                        if ($rulePorts -contains $port -or $rulePorts -contains "Any") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Allows inbound access to sensitive port: $port"
                        }
                    }
                    
                    
                    $broadAddresses = @('Any', '*', '0.0.0.0/0', 'Internet')
                    if ($addresses.RemoteAddress -contains "Any" -or 
                        $addresses.RemoteAddress -contains "*" -or 
                        $addresses.RemoteAddress -contains "Internet") {
                        $isSuspicious = $true
                        $suspiciousReasons += "Allows access from any remote address"
                    }
                }
                
                
                if ($apps.Program -and $rule.Action -eq "Allow" -and $rule.Enabled) {
                    
                    $unusualPaths = @('\\', '%TEMP%', '%AppData%', 'Downloads', 'Temp')
                    foreach ($path in $unusualPaths) {
                        if ($apps.Program -like "*$path*") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Allows access to application in unusual path: $($apps.Program)"
                        }
                    }
                }
                
                
                if ($isSuspicious) {
                    $suspiciousObj = [PSCustomObject]@{
                        RuleName = $rule.Name
                        DisplayName = $rule.DisplayName
                        Reasons = $suspiciousReasons -join ", "
                        Direction = $rule.Direction
                        Action = $rule.Action
                        RemoteAddresses = $addresses.RemoteAddress -join ", "
                        LocalPorts = $ports.LocalPort -join ", "
                        Program = $apps.Program
                        IsEnabled = $rule.Enabled
                    }
                    
                    $suspiciousRules += $suspiciousObj
                }
            }
            catch {
                Write-Log -Message "Error processing firewall rule '$($rule.Name)': $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        
        $advancedSettings = @{}
        try {
            Write-Host "  Retrieving advanced firewall settings..." -ForegroundColor Gray
            
            
            $netshOutput = & netsh advfirewall show global
            
            
            $settingPattern = '(?m)^(\w+[\s\w]+):\s+(.+)$'
            foreach ($line in $netshOutput) {
                if ($line -match $settingPattern) {
                    $settingName = $Matches[1].Trim()
                    $settingValue = $Matches[2].Trim()
                    $advancedSettings[$settingName] = $settingValue
                }
            }
        }
        catch {
            Write-Log -Message "Error retrieving advanced firewall settings: $($_.Exception.Message)" -Level "Warning"
        }
        
        
        $firewallService = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
        $firewallServiceStatus = if ($firewallService) { $firewallService.Status } else { "Unknown" }
        $firewallServiceStartType = if ($firewallService) { $firewallService.StartType } else { "Unknown" }
        
        
        $result = [PSCustomObject]@{
            Profiles = $firewallProfiles
            Rules = $firewallRules
            SuspiciousRules = $suspiciousRules
            AdvancedSettings = $advancedSettings
            ServiceStatus = $firewallServiceStatus
            ServiceStartType = $firewallServiceStartType
            TotalRules = $firewallRules.Count
            EnabledRules = ($firewallRules | Where-Object { $_.Enabled -eq $true }).Count
            InboundAllow = ($firewallRules | Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" }).Count
            OutboundBlock = ($firewallRules | Where-Object { $_.Direction -eq "Outbound" -and $_.Action -eq "Block" }).Count
            SuspiciousRuleCount = $suspiciousRules.Count
            FirewallEnabled = if (($firewallProfiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0) { $true } else { $false }
        }
        
        
        $securityConcerns = @()
        
        
        $disabledProfiles = $firewallProfiles | Where-Object { $_.Enabled -eq $false }
        if ($disabledProfiles) {
            $securityConcerns += "Firewall disabled for profiles: $($disabledProfiles.Name -join ', ')"
        }
        
        
        $permissiveProfiles = $firewallProfiles | Where-Object { $_.DefaultInboundAction -eq "Allow" }
        if ($permissiveProfiles) {
            $securityConcerns += "Default inbound allow for profiles: $($permissiveProfiles.Name -join ', ')"
        }
        
        
        if ($firewallServiceStatus -ne "Running" -or $firewallServiceStartType -eq "Disabled") {
            $securityConcerns += "Windows Firewall service is not running or disabled (Status: $firewallServiceStatus, StartType: $firewallServiceStartType)"
        }
        
        
        if (($firewallProfiles | Where-Object { $_.LogAllowed -eq $true -or $_.LogBlocked -eq $true }).Count -eq 0) {
            $securityConcerns += "Firewall logging is disabled on all profiles"
        }
        
        
        $result | Add-Member -MemberType NoteProperty -Name "SecurityConcerns" -Value $securityConcerns
        
        Write-Host "  Collected information on $($firewallProfiles.Count) firewall profiles and $($firewallRules.Count) firewall rules." -ForegroundColor Green
        Write-Host "  Found $($suspiciousRules.Count) potentially suspicious firewall rules." -ForegroundColor $(if ($suspiciousRules.Count -gt 0) { "Yellow" } else { "Green" })
        
        Write-Log -Message "Collected firewall configuration information: $($firewallProfiles.Count) profiles, $($firewallRules.Count) rules, $($suspiciousRules.Count) suspicious rules." -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error collecting firewall configuration information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting firewall configuration information: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-WirelessNetworkInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$QuickScan
    )
    
    Write-Log -Message "Collecting wireless network information..." -Level "Info"
    Write-Host "Collecting wireless network information..." -ForegroundColor Cyan
    
    
    $wirelessInterfaces = @()
    $wirelessProfiles = @()
    $currentConnections = @()
    $securityIssues = @()
    
    try {
        
        Write-Host "  Checking for wireless interfaces..." -ForegroundColor Gray
        $hasWireless = $false
        
        
        $wifiAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | 
                        Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' -or $_.PhysicalMediaType -eq 'Wireless LAN' }
        
        if ($wifiAdapters -and $wifiAdapters.Count -gt 0) {
            $hasWireless = $true
            Write-Host "  Found $($wifiAdapters.Count) wireless network adapters." -ForegroundColor Gray
        } else {
            Write-Host "  No wireless network adapters found on this system." -ForegroundColor Gray
            Write-Log -Message "No wireless network adapters found on this system." -Level "Info"
            
            
            return [PSCustomObject]@{
                HasWirelessCapability = $false
                WirelessInterfaces = @()
                WirelessProfiles = @()
                CurrentConnections = @()
                SecurityIssues = @()
                TotalInterfaces = 0
                TotalProfiles = 0
                TotalConnections = 0
                SecurityIssueCount = 0
            }
        }
        
        
        Write-Host "  Collecting wireless interface details..." -ForegroundColor Gray
        foreach ($adapter in $wifiAdapters) {
            try {
                
                $ipAddresses = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
                
                
                $ipv4 = ($ipAddresses | Where-Object { $_.AddressFamily -eq "IPv4" } | Select-Object -ExpandProperty IPAddress) -join ", "
                $ipv6 = ($ipAddresses | Where-Object { $_.AddressFamily -eq "IPv6" } | Select-Object -ExpandProperty IPAddress) -join ", "
                
                
                $netConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
                
                
                $interfaceObj = [PSCustomObject]@{
                    Name = $adapter.Name
                    Description = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    MacAddress = $adapter.MacAddress
                    Speed = "$($adapter.LinkSpeed)"
                    IPv4Address = $ipv4
                    IPv6Address = $ipv6
                    Gateway = $netConfig.IPv4DefaultGateway.NextHop
                    DNSServers = ($netConfig.DNSServer | Where-Object { $_.Address -ne $null } | ForEach-Object { $_.Address }) -join ", "
                }
                
                $wirelessInterfaces += $interfaceObj
                
                
                if ($adapter.Status -eq "Up") {
                    $isRandomized = $false
                    $netshOutput = & netsh wlan show interface name="$($adapter.Name)" | Select-String "Hosted network"
                    if ($netshOutput -and $netshOutput -notmatch "Not started") {
                        $securityIssues += [PSCustomObject]@{
                            Type = "Hosted Network Active"
                            Description = "Wireless adapter is hosting a network which could be a sign of compromise or unauthorized access point"
                            Interface = $adapter.Name
                            Severity = "High"
                        }
                    }
                }
            }
            catch {
                Write-Log -Message "Error collecting wireless interface details for $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        
        Write-Host "  Collecting wireless profile information..." -ForegroundColor Gray
        
        try {
            
            $netshProfiles = & netsh wlan show profiles
            $profileNames = @()
            $profileNamePattern = 'All User Profile\s+:\s+(.+)$'
            foreach ($line in $netshProfiles) {
                if ($line -match $profileNamePattern) {
                    $profileNames += $Matches[1].Trim()
                }
            }
            
            
            foreach ($profileName in $profileNames) {
                try {
      
                    $profileInfo = & netsh wlan show profile name="`"$profileName`"" key=clear 
                    $ssid = ""
                    $authType = ""
                    $encryption = ""
                    $keyType = ""
                    $keyContent = ""
                    $connectionMode = ""
                    $ssidPattern = 'SSID name\s+:\s+(.+)$'
                    foreach ($line in $profileInfo) {
                        if ($line -match $ssidPattern) {
                            $ssid = $Matches[1].Trim()
                            break
                        }
                    }
                    
                    $authPattern = 'Authentication\s+:\s+(.+)$'
                    foreach ($line in $profileInfo) {
                        if ($line -match $authPattern) {
                            $authType = $Matches[1].Trim()
                            break
                        }
                    }
                    
                    $encPattern = 'Encryption\s+:\s+(.+)$'
                    foreach ($line in $profileInfo) {
                        if ($line -match $encPattern) {
                            $encryption = $Matches[1].Trim()
                            break
                        }
                    }
                    
                    $keyTypePattern = 'Key Content\s+:\s+(.+)$'
                    foreach ($line in $profileInfo) {
                        if ($line -match $keyTypePattern) {
                            $keyContent = $Matches[1].Trim()
                            break
                        }
                    }
                    
                    $modePattern = 'Connection mode\s+:\s+(.+)$'
                    foreach ($line in $profileInfo) {
                        if ($line -match $modePattern) {
                            $connectionMode = $Matches[1].Trim()
                            break
                        }
                    }
                    
                    $profileObj = [PSCustomObject]@{
                        ProfileName = $profileName
                        SSID = $ssid
                        AuthenticationType = $authType
                        Encryption = $encryption
                        KeyContent = if ($keyContent) { "Available" } else { "Not available" }
                        ConnectionMode = $connectionMode
                        IsSecure = ($authType -ne "Open") -and ($encryption -ne "None")
                    }
                    
                    $wirelessProfiles += $profileObj
                    if ($authType -eq "Open" -or $encryption -eq "None") {
                        $securityIssues += [PSCustomObject]@{
                            Type = "Insecure Profile"
                            Description = "Wireless profile '$profileName' uses insecure authentication: $authType, encryption: $encryption"
                            Interface = "N/A"
                            Severity = "High"
                        }
                    }
                    elseif ($authType -eq "WEP") {
                        $securityIssues += [PSCustomObject]@{
                            Type = "Weak Authentication"
                            Description = "Wireless profile '$profileName' uses deprecated WEP authentication which is easily broken"
                            Interface = "N/A"
                            Severity = "High"
                        }
                    }
                    elseif ($authType -eq "WPA-Personal" -and $keyContent) {
                        if ($keyContent.Length -lt 8) {
                            $securityIssues += [PSCustomObject]@{
                                Type = "Weak Password"
                                Description = "Wireless profile '$profileName' uses a short password (less than 8 characters)"
                                Interface = "N/A"
                                Severity = "Medium"
                            }
                        }
                    }
                }
                catch {
                    Write-Log -Message "Error processing wireless profile '$profileName': $($_.Exception.Message)" -Level "Warning"
                }
            }
        }
        catch {
            Write-Log -Message "Error collecting wireless profiles: $($_.Exception.Message)" -Level "Warning"
        }
        Write-Host "  Collecting current wireless connection details..." -ForegroundColor Gray
        
        try {
            foreach ($adapter in $wifiAdapters | Where-Object { $_.Status -eq "Up" }) {
                $connectionDetails = & netsh wlan show interfaces
                $state = ""
                $ssid = ""
                $bssid = ""
                $networkType = ""
                $radioType = ""
                $authentication = ""
                $encryption = ""
                $channel = ""
                $signal = ""
                $rxRate = ""
                $txRate = ""
                $statePattern = 'State\s+:\s+(.+)$'
                $ssidPattern = 'SSID\s+:\s+(.+)$'
                $bssidPattern = 'BSSID\s+:\s+(.+)$'
                $networkTypePattern = 'Network type\s+:\s+(.+)$'
                $radioTypePattern = 'Radio type\s+:\s+(.+)$'
                $authPattern = 'Authentication\s+:\s+(.+)$'
                $encPattern = 'Encryption\s+:\s+(.+)$'
                $channelPattern = 'Channel\s+:\s+(.+)$'
                $signalPattern = 'Signal\s+:\s+(.+)$'
                $rxRatePattern = 'Receive rate \(Mbps\)\s+:\s+(.+)$'
                $txRatePattern = 'Transmit rate \(Mbps\)\s+:\s+(.+)$'
                
                foreach ($line in $connectionDetails) {
                    if ($line -match $statePattern) { $state = $Matches[1].Trim() }
                    if ($line -match $ssidPattern) { $ssid = $Matches[1].Trim() }
                    if ($line -match $bssidPattern) { $bssid = $Matches[1].Trim() }
                    if ($line -match $networkTypePattern) { $networkType = $Matches[1].Trim() }
                    if ($line -match $radioTypePattern) { $radioType = $Matches[1].Trim() }
                    if ($line -match $authPattern) { $authentication = $Matches[1].Trim() }
                    if ($line -match $encPattern) { $encryption = $Matches[1].Trim() }
                    if ($line -match $channelPattern) { $channel = $Matches[1].Trim() }
                    if ($line -match $signalPattern) { $signal = $Matches[1].Trim() }
                    if ($line -match $rxRatePattern) { $rxRate = $Matches[1].Trim() }
                    if ($line -match $txRatePattern) { $txRate = $Matches[1].Trim() }
                }
                
                if ($ssid) {
                    $connectionObj = [PSCustomObject]@{
                        AdapterName = $adapter.Name
                        State = $state
                        SSID = $ssid
                        BSSID = $bssid
                        NetworkType = $networkType
                        RadioType = $radioType
                        Authentication = $authentication
                        Encryption = $encryption
                        Channel = $channel
                        SignalQuality = $signal
                        ReceiveRate = $rxRate
                        TransmitRate = $txRate
                    }
                    
                    $currentConnections += $connectionObj
                    if ($authentication -eq "Open" -or $encryption -eq "None") {
                        $securityIssues += [PSCustomObject]@{
                            Type = "Insecure Connection"
                            Description = "Currently connected to '$ssid' using insecure authentication: $authentication, encryption: $encryption"
                            Interface = $adapter.Name
                            Severity = "Critical"
                        }
                    }
                    
                    if ($signal -and $signal -match "(\d+)%" -and [int]$Matches[1] -lt 50) {
                        $securityIssues += [PSCustomObject]@{
                            Type = "Weak Signal"
                            Description = "Connection to '$ssid' has a weak signal ($signal) which may lead to instability"
                            Interface = $adapter.Name
                            Severity = "Low"
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Error collecting current wireless connection: $($_.Exception.Message)" -Level "Warning"
        }
        
        if (-not $QuickScan) {
            Write-Host "  Collecting additional wireless connection history..." -ForegroundColor Gray
            
            try {
                $wifiEvents = Get-WinEvent -LogName "Microsoft-Windows-WLAN-AutoConfig/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue |
                              Where-Object { $_.Id -eq 8001 -or $_.Id -eq 11001 }
                
                $uniqueNetworks = @{}
                
                foreach ($event in $wifiEvents) {
                    try {
                        $eventXml = [xml]$event.ToXml()
                        $ssid = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq "SSID" } | Select-Object -ExpandProperty "#text"
                        
                        if ($ssid -and -not $uniqueNetworks.ContainsKey($ssid)) {
                            $uniqueNetworks[$ssid] = $true
                            if ($wirelessProfiles | Where-Object { $_.SSID -eq $ssid }) {
                            } else {
                                $securityIssues += [PSCustomObject]@{
                                    Type = "Unknown Network Connection"
                                    Description = "Connection detected to wireless network '$ssid' which has no saved profile"
                                    Interface = "Unknown"
                                    Severity = "Medium"
                                }
                            }
                        }
                    }
                    catch {
                        write-host "event parsing errors occured, continue.."
                    }
                }
            }
            catch {
                Write-Log -Message "Error collecting wireless connection history: $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        try {
            $hostedNetworkOutput = & netsh wlan show hostednetwork
            if ($hostedNetworkOutput -and $hostedNetworkOutput -match "Started") {
                $securityIssues += [PSCustomObject]@{
                    Type = "Hosted Network Running"
                    Description = "System is hosting a wireless network which could indicate a compromise or unauthorized access point"
                    Interface = "System-wide"
                    Severity = "Critical"
                }
            }
        }
        catch {
            Write-Log -Message "Error checking for hosted networks: $($_.Exception.Message)" -Level "Warning"
        }
        
        $result = [PSCustomObject]@{
            HasWirelessCapability = $hasWireless
            WirelessInterfaces = $wirelessInterfaces
            WirelessProfiles = $wirelessProfiles
            CurrentConnections = $currentConnections
            SecurityIssues = $securityIssues
            TotalInterfaces = $wirelessInterfaces.Count
            TotalProfiles = $wirelessProfiles.Count
            TotalConnections = $currentConnections.Count
            SecurityIssueCount = $securityIssues.Count
        }
        
        Write-Host "  Collected information on $($wirelessInterfaces.Count) wireless interfaces, $($wirelessProfiles.Count) profiles, and $($currentConnections.Count) active connections." -ForegroundColor Green
        Write-Host "  Identified $($securityIssues.Count) potential security issues with wireless configuration." -ForegroundColor $(if ($securityIssues.Count -gt 0) { "Yellow" } else { "Green" })
        
        Write-Log -Message "Collected wireless network information: $($wirelessInterfaces.Count) interfaces, $($wirelessProfiles.Count) profiles, $($currentConnections.Count) connections, $($securityIssues.Count) security issues." -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error collecting wireless network information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting wireless network information: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-NetworkServiceInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$QuickScan
    )

    $networkServices = @()
    $networkDrivers = @()
    $criticalServices = @()
    $suspiciousServices = @()

    try {
        $knownNetworkServices = @('Dhcp', 'Dnscache', 'netprofm', 'NlaSvc')
        $allServices = Get-Service -ErrorAction Stop

        foreach ($service in $allServices) {
            if ($knownNetworkServices -contains $service.Name) {
                $networkServices += [PSCustomObject]@{
                    Name        = $service.Name
                    DisplayName = $service.DisplayName
                    Status      = $service.Status
                }
            }
            $serviceWMI = Get-WmiObject Win32_Service -Filter "Name = '$($service.Name)'" -ErrorAction SilentlyContinue
            if ($serviceWMI -and ($serviceWMI.StartName -match 'LocalSystem|NetworkService|LocalService')) {
                if ($serviceWMI.PathName -match "http|ftp|curl|wget|powershell.*Invoke-WebRequest") {
                    $suspiciousServices += [PSCustomObject]@{
                        Name        = $service.Name
                        Issue       = "Service potentially calling out to network"
                        Severity    = "High"
                        StartName   = $serviceWMI.StartName
                        BinaryPath  = $serviceWMI.PathName
                    }
                }
            }
        }
        $drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue
        foreach ($driver in $drivers) {
            if ($driver.PathName -match "ndis|tcpip|netadapter|miniport") {
                $networkDrivers += [PSCustomObject]@{
                    Name        = $driver.Name
                    DisplayName = $driver.DisplayName
                    Path        = $driver.PathName
                    State       = $driver.State
                }
            }
        }

        if (-not $QuickScan) {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" }
            foreach ($task in $tasks) {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
                if ($taskInfo.NextRunTime -ne $null -and $taskInfo.NextRunTime -gt (Get-Date)) {
                    foreach ($action in $task.Actions) {
                        $actionString = $action.ToString()
                        if ($actionString -match "wget|curl|ftp|Invoke-WebRequest") {
                            $suspiciousServices += [PSCustomObject]@{
                                Name        = "$($task.TaskPath)$($task.TaskName)"
                                Issue       = "Suspicious scheduled task with potential network call"
                                Severity    = "Medium"
                                BinaryPath  = $actionString
                            }
                        }
                    }
                }
            }
        }

        return [PSCustomObject]@{
            NetworkServices    = $networkServices
            NetworkDrivers     = $networkDrivers
            CriticalServices   = $criticalServices
            SuspiciousFindings = $suspiciousServices
        }

    } catch {
        Write-Host "Error during service analysis: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-NetworkEventLogs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$QuickScan,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 1000,
        
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 7
    )
    
    Write-Log -Message "Collecting network-related event logs..." -Level "Info"
    Write-Host "Collecting network-related event logs..." -ForegroundColor Cyan

    $filteredEvents = @()
    $eventSummary = @()
    $securityEvents = @()
    $firewallEvents = @()
    $dhcpEvents = @()
    $remoteAccessEvents = @()
    $suspiciousEvents = @()
    
    try {
        $startDate = (Get-Date).AddDays(-$DaysBack)
        $relevantLogs = @(
            @{Name = "System"; Relevance = "High"},
            @{Name = "Security"; Relevance = "High"},
            @{Name = "Application"; Relevance = "Medium"},
            @{Name = "Microsoft-Windows-DHCP-Client/Admin"; Relevance = "High"},
            @{Name = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; Relevance = "High"},
            @{Name = "Microsoft-Windows-NetworkProfile/Operational"; Relevance = "High"},
            @{Name = "Microsoft-Windows-RemoteAccess-RemoteAccessConnection/Operational"; Relevance = "High"},
            @{Name = "Microsoft-Windows-WLAN-AutoConfig/Operational"; Relevance = "High"},
            @{Name = "Microsoft-Windows-SMBClient/Operational"; Relevance = "Medium"},
            @{Name = "Microsoft-Windows-SMBServer/Operational"; Relevance = "Medium"},
            @{Name = "Microsoft-Windows-DNS-Client/Operational"; Relevance = "Medium"},
            @{Name = "Microsoft-Windows-WinRM/Operational"; Relevance = "Medium"},
            @{Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; Relevance = "Medium"},
            @{Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; Relevance = "Medium"}
        )
        
        if ($QuickScan) {
            $relevantLogs = $relevantLogs | Where-Object { $_.Relevance -eq "High" }
            Write-Log -Message "QuickScan enabled - only checking high relevance logs" -Level "Info"
        }
        
        $eventIdMap = @{
            "System" = @{
                "NetworkInterface" = @(27, 4202, 4199, 4201, 4202, 4203);
                "Firewall" = @(7036, 7040, 7024, 7031); 
                "DHCP" = @(1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008); 
                "DNS" = @(1014, 1016, 1011, 1012, 1020, 1073742824); 
                "TCPIP" = @(4227, 4228, 4231, 4260); 
                "IPsec" = @(4277, 4279, 4284, 4285, 4286, 4291); 
                "Services" = @(7022, 7023, 7024, 7031, 7034, 7036, 7040, 7045);
                "Time" = @(35, 36, 37, 129, 144, 157);
            };
            "Security" = @{
                "Authentication" = @(4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779); 
                "NetworkPolicy" = @(4818, 4820, 4902, 4904); 
                "IPsec" = @(4960, 4961, 4962, 4963, 4964, 4965, 4976, 4977, 4978, 4979, 4980, 4981, 4982, 4983, 4984, 4985); 
                "Firewall" = @(4944, 4945, 4946, 4947, 4948, 4950, 4954, 4956); 
                "RemoteAccess" = @(4649, 4675, 4697, 4698, 4699, 4700, 4701, 4702, 4704, 4705, 4706, 4707, 4712, 4713); 
                "Groups" = @(4728, 4729, 4732, 4733, 4735, 4737, 4755, 4756, 4761, 4762, 4785, 4786);
            };
            

            "Microsoft-Windows-DHCP-Client/Admin" = @{
                "All" = @(10000, 10001, 10002, 10003, 10004, 10006, 10007, 10008, 10009, 10010, 10011, 10012, 10013, 10014, 10015, 10016, 10017, 10018, 10019, 10020, 10021, 10022, 10023, 10024, 10025, 10026, 10027, 10028, 10029, 10030, 10031, 10032, 10033, 10034, 10035, 10036, 10037, 10038);
            };

            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" = @{
                "All" = @(2001, 2002, 2003, 2004, 2005, 2006, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024);
            };
            "Microsoft-Windows-NetworkProfile/Operational" = @{
                "All" = @(10000, 10001, 10002, 10003, 10004, 10005, 10006);
            };

            "Microsoft-Windows-RemoteAccess-RemoteAccessConnection/Operational" = @{
                "All" = @(20000, 20001, 20002, 20003, 20004, 20005, 20006, 20008, 20009, 20010, 20011, 20012, 20013, 20014, 20015, 20016, 20050, 20227, 20229, 20275);
            };

            "Microsoft-Windows-WLAN-AutoConfig/Operational" = @{
                "All" = @(8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009, 8010, 8011, 8012, 8013);
            };

            "Microsoft-Windows-SMBClient/Operational" = @{
                "All" = @(30800, 30803, 30804, 30805, 30806, 30807, 30808, 30809, 31001);
            };

            "Microsoft-Windows-SMBServer/Operational" = @{
                "All" = @(1020, 1022, 1024, 1026, 1028, 1030, 1031, 1032, 1033, 1034);
            };

            "Microsoft-Windows-DNS-Client/Operational" = @{
                "All" = @(1010, 1012, 1014, 3006, 3008, 3010, 3020);
            };

            "Microsoft-Windows-WinRM/Operational" = @{
                "All" = @(6, 8, 11, 12, 15, 16, 18, 31, 33, 101, 103, 104, 105, 106, 107, 131, 132, 133, 134, 142, 144, 145, 168);
            };

            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" = @{
                "All" = @(1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111);
            };

            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" = @{
                "All" = @(21, 22, 23, 24, 25, 39, 40);
            };
        }

        $suspiciousPatterns = @(
            @{
                EventID = 4624;
                LogName = "Security";
                Patterns = @{
                    "LogonType" = @{
                        Values = @(3, 10);  # type 3 = network, type 10 = RemoteInteractive
                        Match = "Unusual remote logon type detected";
                    };
                };
                Severity = "Medium";
            },

            @{
                EventID = 4625;
                LogName = "Security";
                Patterns = @{
                    "FailureReason" = @{
                        Values = @("*");
                        Match = "Failed logon attempt";
                    };
                };
                Severity = "Medium";
            },
            @{
                EventID = 7045;
                LogName = "System";
                Patterns = @{
                    "ServiceName" = @{
                        Values = @("*vnc*", "*remote*", "*admin*", "*rat*", "*backdoor*", "*proxy*", "*tunnel*");
                        Match = "Potentially suspicious service installed";
                    };
                    "ImagePath" = @{
                        Values = @("*%temp%*", "*powershell*", "*cmd.exe*", "*regsvr32*", "*certutil*", "*bitsadmin*");
                        Match = "Service with suspicious execution path";
                    };
                };
                Severity = "High";
            },

            @{
                EventID = 2004;
                LogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";
                Patterns = @{
                    "RuleName" = @{
                        Values = @("*");
                        Match = "Firewall rule modified";
                    };
                };
                Severity = "Medium";
            },
            @{
                EventID = 1149;
                LogName = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
                Patterns = @{
                    "User" = @{
                        Values = @("*");
                        Match = "Remote Desktop connection attempt";
                    };
                };
                Severity = "Medium";
            }
        )
       
        $logCount = $relevantLogs.Count
        $currentLog = 0
        
        foreach ($log in $relevantLogs) {
            $currentLog++
            
            Write-Host "  Checking $($log.Name) event log ($currentLog of $logCount)..." -ForegroundColor Gray
            
            try {
                $logExists = Get-WinEvent -ListLog $log.Name -ErrorAction SilentlyContinue
                
                if (-not $logExists) {
                    Write-Log -Message "Event log $($log.Name) does not exist or is not accessible" -Level "Warning"
                    continue
                }
                $relevantIds = @()
                if ($eventIdMap.ContainsKey($log.Name)) {
                    foreach ($category in $eventIdMap[$log.Name].Keys) {
                        $relevantIds += $eventIdMap[$log.Name][$category]
                    }
                }
                if ($relevantIds.Count -eq 0) {
                    Write-Log -Message "No relevant event IDs defined for log $($log.Name)" -Level "Warning"
                    continue
                }
                $filterXPath = "*[System[TimeCreated[@SystemTime>='{0}']]]" -f $startDate.ToUniversalTime().ToString("o")
                
                $events = Get-WinEvent -LogName $log.Name -MaxEvents $MaxEvents -FilterXPath $filterXPath -ErrorAction SilentlyContinue
                
                if (-not $events) {
                    Write-Log -Message "No events found in log $($log.Name) within the specified time range" -Level "Info"
                    continue
                }
                
                $filteredLogEvents = $events | Where-Object { $relevantIds -contains $_.Id }
                
                if (-not $filteredLogEvents -or $filteredLogEvents.Count -eq 0) {
                    Write-Log -Message "No relevant events found in log $($log.Name)" -Level "Info"
                    continue
                }
                
                Write-Log -Message "Found $($filteredLogEvents.Count) relevant events in log $($log.Name)" -Level "Info"
                
                foreach ($event in $filteredLogEvents) {
                    try {
                        $eventXml = [xml]$event.ToXml()
                        $eventData = @{}
                        if ($eventXml.Event.EventData -and $eventXml.Event.EventData.Data) {
                            foreach ($dataItem in $eventXml.Event.EventData.Data) {
                                if ($dataItem.Name) {
                                    $eventData[$dataItem.Name] = $dataItem.'#text'
                                }
                            }
                        }
                        $eventObj = [PSCustomObject]@{
                            TimeCreated = $event.TimeCreated
                            LogName = $event.LogName
                            EventID = $event.Id
                            Level = $event.LevelDisplayName
                            Message = $event.Message
                            RecordID = $event.RecordId
                            ProviderName = $event.ProviderName
                            EventData = $eventData
                        }
                        $filteredEvents += $eventObj
                        if ($event.LogName -eq "Security") {
                            $securityEvents += $eventObj
                        }
                        elseif ($event.LogName -like "*Firewall*") {
                            $firewallEvents += $eventObj
                        }
                        elseif ($event.LogName -like "*DHCP*") {
                            $dhcpEvents += $eventObj
                        }
                        elseif ($event.LogName -like "*RemoteAccess*" -or $event.LogName -like "*TerminalServices*") {
                            $remoteAccessEvents += $eventObj
                        }
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($event.Id -eq $pattern.EventID -and $event.LogName -like "*$($pattern.LogName)*") {
                                $isMatch = $false
                                $matchDescription = ""
                                foreach ($field in $pattern.Patterns.Keys) {
                                    $fieldValues = $pattern.Patterns[$field].Values
                                    $matchText = $pattern.Patterns[$field].Match
                                    $fieldValue = $null
                                    if ($eventData.ContainsKey($field)) {
                                        $fieldValue = $eventData[$field]
                                    }
                                    elseif ($event.Message -match "$field\s*:\s*([^\r\n]+)") {
                                        $fieldValue = $Matches[1]
                                    }
                                    if ($fieldValue) {
                                        foreach ($value in $fieldValues) {
                                            if ($fieldValue -like $value) {
                                                $isMatch = $true
                                                $matchDescription = $matchText
                                                break
                                            }
                                        }
                                    }
                                    
                                    if ($isMatch) {
                                        break
                                    }
                                }
                                
                                if ($isMatch) {
                                    $suspiciousEvents += [PSCustomObject]@{
                                        TimeCreated = $event.TimeCreated
                                        LogName = $event.LogName
                                        EventID = $event.Id
                                        Level = $event.LevelDisplayName
                                        Message = $event.Message
                                        MatchDescription = $matchDescription
                                        Severity = $pattern.Severity
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Log -Message "Error processing event: $($_.Exception.Message)" -Level "Warning"
                    }
                }
                
                $logSummary = [PSCustomObject]@{
                    LogName = $log.Name
                    TotalEvents = $events.Count
                    RelevantEvents = $filteredLogEvents.Count
                    EventIDs = ($filteredLogEvents | Group-Object -Property Id | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
                    EarliestEvent = if ($filteredLogEvents) { ($filteredLogEvents | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated } else { $null }
                    LatestEvent = if ($filteredLogEvents) { ($filteredLogEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated } else { $null }
                }
                
                $eventSummary += $logSummary
                
                Write-Host "    Found $($filteredLogEvents.Count) relevant events out of $($events.Count) total events." -ForegroundColor Gray
            }
            catch {
                Write-Log -Message "Error processing log $($log.Name): $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        $eventFrequency = $filteredEvents | Group-Object -Property EventID, LogName | ForEach-Object {
            $parts = $_.Name -split ', '
            [PSCustomObject]@{
                EventID = $parts[0]
                LogName = $parts[1]
                Count = $_.Count
                Description = if ($_.Group[0].Message) { $_.Group[0].Message.Split('.')[0] } else { "N/A" }
            }
        } | Sort-Object -Property Count -Descending
        
        $suspiciousTimeline = $suspiciousEvents | Sort-Object -Property TimeCreated
        $result = [PSCustomObject]@{
            FilteredEvents = $filteredEvents
            EventSummary = $eventSummary
            SecurityEvents = $securityEvents
            FirewallEvents = $firewallEvents
            DHCPEvents = $dhcpEvents
            RemoteAccessEvents = $remoteAccessEvents
            SuspiciousEvents = $suspiciousEvents
            EventFrequency = $eventFrequency
            SuspiciousTimeline = $suspiciousTimeline
            TotalEventsCollected = $filteredEvents.Count
            TotalSecurityEvents = $securityEvents.Count
            TotalFirewallEvents = $firewallEvents.Count
            TotalDHCPEvents = $dhcpEvents.Count
            TotalRemoteAccessEvents = $remoteAccessEvents.Count
            TotalSuspiciousEvents = $suspiciousEvents.Count
            TimeRange = [PSCustomObject]@{
                StartDate = $startDate
                EndDate = Get-Date
                DaysBack = $DaysBack
            }
        }
        
        Write-Host "  Collected $($filteredEvents.Count) network-related events from event logs." -ForegroundColor Green
        Write-Host "  Found $($suspiciousEvents.Count) potentially suspicious events." -ForegroundColor $(if ($suspiciousEvents.Count -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  Security: $($securityEvents.Count), Firewall: $($firewallEvents.Count), DHCP: $($dhcpEvents.Count), Remote Access: $($remoteAccessEvents.Count)" -ForegroundColor Green
        
        Write-Log -Message "Collected network event logs: $($filteredEvents.Count) events, $($suspiciousEvents.Count) suspicious events, spanning $DaysBack days." -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error collecting network event logs: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error collecting network event logs: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-NetworkSecurityAnalysis {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$QuickScan,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$NetworkData,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$FirewallData,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$WirelessData,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$NetworkServiceData,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$EventLogData
    )
    
    Write-Log -Message "Performing network security analysis..." -Level "Info"
    Write-Host "Performing network security analysis..." -ForegroundColor Cyan
    $securityFindings = @()
    $vulnerabilities = @()
    $anomalies = @()
    $recommendations = @()
    $securityMetrics = @{}
    
    try {
        Write-Host "  Analyzing network configuration..." -ForegroundColor Gray
        
        if ($NetworkData) {
            if ($NetworkData.Interfaces) {
                foreach ($interface in $NetworkData.Interfaces) {
                    $publicDnsServers = @('8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222', '208.67.220.220')
                    $interfaceDns = $interface.DNSServers -split ', '
                    
                    foreach ($dns in $interfaceDns) {
                        if ($publicDnsServers -contains $dns) {
                            $securityFindings += [PSCustomObject]@{
                                Category = "Network Configuration"
                                Title = "Public DNS Server Configured"
                                Severity = "Low"
                                Description = "Interface '$($interface.Name)' is using public DNS server $dns which may indicate manual network configuration changes"
                                Component = "Interface: $($interface.Name)"
                                Recommendation = "Verify this DNS configuration is intended and not the result of malware changing DNS settings"
                            }
                        }
                    }
                    if ($interface.Status -eq "Up" -and $interface.Description -match "TAP|VPN|Tunnel|Virtual|VM") {
                        $securityFindings += [PSCustomObject]@{
                            Category = "Network Configuration"
                            Title = "Virtual or VPN Interface Active"
                            Severity = "Medium"
                            Description = "Active virtual network interface detected: $($interface.Name) ($($interface.Description))"
                            Component = "Interface: $($interface.Name)"
                            Recommendation = "Verify this virtual interface is intended and part of authorized software"
                        }
                    }
                }
            }
            
            if ($NetworkData.Connections -and $NetworkData.Connections.Connections) {
                $riskyPorts = @{
                    22 = "SSH"
                    23 = "Telnet"
                    445 = "SMB"
                    135 = "RPC"
                    139 = "NetBIOS"
                    3389 = "RDP"
                    4444 = "Metasploit Default"
                    5800 = "VNC"
                    5900 = "VNC"
                }

                $listeners = $NetworkData.Connections.Connections | Where-Object { $_.State -eq 'Listen' }
                foreach ($listener in $listeners) {
                    if ($riskyPorts.ContainsKey([int]$listener.LocalPort)) {
                        $severity = if ($listener.LocalAddress -eq "0.0.0.0" -or $listener.LocalAddress -eq "::") { "High" } else { "Medium" }
                        
                        $securityFindings += [PSCustomObject]@{
                            Category = "Network Exposure"
                            Title = "Sensitive Port Listening"
                            Severity = $severity
                            Description = "$($riskyPorts[[int]$listener.LocalPort]) service listening on port $($listener.LocalPort) via process $($listener.ProcessName) (PID: $($listener.ProcessId))"
                            Component = "Process: $($listener.ProcessName)"
                            Recommendation = "Verify this service is needed and restrict access using the firewall if possible"
                        }
                    }
                }
                

                $suspiciousPortsOutbound = @(445, 135, 139, 21, 22, 23, 25, 1433, 3306, 5432)
                $outboundConnections = $NetworkData.Connections.Connections | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' }
                
                foreach ($connection in $outboundConnections) {
                    if ($suspiciousPortsOutbound -contains [int]$connection.RemotePort) {
                        $securityFindings += [PSCustomObject]@{
                            Category = "Network Activity"
                            Title = "Suspicious Outbound Connection"
                            Severity = "Medium"
                            Description = "Outbound connection to potentially suspicious port $($connection.RemotePort) on $($connection.RemoteAddress) from process $($connection.ProcessName) (PID: $($connection.ProcessId))"
                            Component = "Process: $($connection.ProcessName)"
                            Recommendation = "Investigate process making this connection and verify it is legitimate"
                        }
                    }
                    

                    $suspiciousProcesses = @('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'rundll32.exe', 'mshta.exe')
                    if ($suspiciousProcesses -contains $connection.ProcessName) {
                        $securityFindings += [PSCustomObject]@{
                            Category = "Network Activity"
                            Title = "Suspicious Process Making Network Connection"
                            Severity = "High"
                            Description = "Potential command and control or lateral movement: $($connection.ProcessName) connecting to $($connection.RemoteAddress):$($connection.RemotePort)"
                            Component = "Process: $($connection.ProcessName)"
                            Recommendation = "Urgently investigate this process and its network activity"
                        }
                    }
                }
            }
            
            if ($NetworkData.RoutingInformation -and $NetworkData.RoutingInformation.Routes) {
                $suspiciousRoutes = $NetworkData.RoutingInformation.Routes | Where-Object {
                    $_.DestinationPrefix -match "^0\." -or  # Check for default routes
                    ($_.NextHop -ne "0.0.0.0" -and $_.NextHop -ne "::" -and $_.NextHop -ne "127.0.0.1" -and $_.NextHop -ne "::1")
                }
                
                foreach ($route in $suspiciousRoutes) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "Network Configuration"
                        Title = "Unusual Routing Configuration"
                        Severity = "Medium"
                        Description = "Unusual route detected: $($route.DestinationPrefix) via $($route.NextHop)"
                        Component = "Routing Table"
                        Recommendation = "Verify this route is intentional and legitimate"
                    }
                }
            }
            
            if ($NetworkData.DNSCacheInformation -and $NetworkData.DNSCacheInformation.CacheEntries) {
                $suspiciousDomains = $NetworkData.DNSCacheInformation.CacheEntries | Where-Object {
                    $_.Name -match "\d+\.\d+\.\d+\.\d+" -or  #ip address in domain name
                    $_.Name -match "^[a-zA-Z0-9]{16,}" -or    #long random looking domain
                    $_.Name -match "\.tk$|\.cc$|\.ru$" -or    #potentially suspicious TLDs
                    $_.Name -match "googledocs\.net" -or      #typosquatting examples
                    $_.Name -match "micosoft\.com" -or
                    $_.Name -match "paypa1\.com"
                }
                
                foreach ($domain in $suspiciousDomains) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "DNS Activity"
                        Title = "Suspicious Domain in DNS Cache"
                        Severity = "Medium"
                        Description = "Potentially suspicious domain in DNS cache: $($domain.Name) resolves to $($domain.Data)"
                        Component = "DNS Cache"
                        Recommendation = "Investigate system for potential malware and check which process accessed this domain"
                    }
                }
            }

            if ($NetworkData.DNSCacheInformation -and $NetworkData.DNSCacheInformation.HostsFileEntries) {
                $suspiciousHostsEntries = $NetworkData.DNSCacheInformation.HostsFileEntries | Where-Object {
                    $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "::1" -and
                    ($_.Hostnames -match "google\.com|gmail\.com|microsoft\.com|windows\.com|facebook\.com|apple\.com|icloud\.com|paypal\.com")
                }
                
                foreach ($entry in $suspiciousHostsEntries) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "DNS Configuration"
                        Title = "Suspicious Hosts File Entry"
                        Severity = "High"
                        Description = "Potential DNS hijacking in hosts file: $($entry.Line)"
                        Component = "Hosts File"
                        Recommendation = "Remove this entry from the hosts file unless it has a legitimate purpose"
                    }
                }
            }
            
            if ($NetworkData.NetworkShareInformation -and $NetworkData.NetworkShareInformation.LocalShares) {
                $nonStandardShares = $NetworkData.NetworkShareInformation.LocalShares | Where-Object {
                    -not $_.IsSystemShare -and $_.Name -ne 'ADMIN$' -and $_.Name -ne 'IPC$' -and $_.Name -ne 'C$'
                }
                
                foreach ($share in $nonStandardShares) {
                    $hasEveryoneAccess = $share.Permissions | Where-Object { 
                        $_.AccountName -eq 'Everyone' -and $_.AccessRight -eq 'Full' 
                    }
                    
                    if ($hasEveryoneAccess) {
                        $securityFindings += [PSCustomObject]@{
                            Category = "Network Exposure"
                            Title = "Insecure File Share"
                            Severity = "High"
                            Description = "Share '$($share.Name)' grants full access to Everyone"
                            Component = "File Share: $($share.Name)"
                            Recommendation = "Restrict share permissions to only necessary users/groups"
                        }
                    } else {
                        $securityFindings += [PSCustomObject]@{
                            Category = "Network Configuration"
                            Title = "Custom File Share"
                            Severity = "Low"
                            Description = "Custom share '$($share.Name)' detected at path '$($share.Path)'"
                            Component = "File Share: $($share.Name)"
                            Recommendation = "Verify this share is necessary and has appropriate permissions"
                        }
                    }
                }
            }
        }
        
        Write-Host "  Analyzing firewall configuration..." -ForegroundColor Gray
        if ($FirewallData) {
            if ($FirewallData.Profiles) {
                foreach ($profile in $FirewallData.Profiles) {
                    if (-not $profile.Enabled) {
                        $securityFindings += [PSCustomObject]@{
                            Category = "Firewall"
                            Title = "Firewall Profile Disabled"
                            Severity = "High"
                            Description = "Windows Firewall is disabled for the $($profile.Name) profile"
                            Component = "Firewall Profile: $($profile.Name)"
                            Recommendation = "Enable the Windows Firewall for this profile unless another firewall solution is in use"
                        }
                    }
                    
                    if ($profile.DefaultInboundAction -eq "Allow") {
                        $securityFindings += [PSCustomObject]@{
                            Category = "Firewall"
                            Title = "Permissive Firewall Configuration"
                            Severity = "Critical"
                            Description = "Windows Firewall default inbound action is set to Allow for the $($profile.Name) profile"
                            Component = "Firewall Profile: $($profile.Name)"
                            Recommendation = "Change default inbound action to Block for this profile"
                        }
                    }
                }
            }
            
            if ($FirewallData.SuspiciousRules) {
                foreach ($rule in $FirewallData.SuspiciousRules) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "Firewall"
                        Title = "Suspicious Firewall Rule"
                        Severity = if ($rule.IsEnabled) { "High" } else { "Medium" }
                        Description = "Suspicious firewall rule '$($rule.DisplayName)': $($rule.Reasons)"
                        Component = "Firewall Rule: $($rule.DisplayName)"
                        Recommendation = "Review and remove this rule if not required"
                    }
                }
            }

            if ($FirewallData.ServiceStatus -ne "Running") {
                $securityFindings += [PSCustomObject]@{
                    Category = "Firewall"
                    Title = "Firewall Service Not Running"
                    Severity = "Critical"
                    Description = "Windows Defender Firewall service is not running (Status: $($FirewallData.ServiceStatus))"
                    Component = "Firewall Service"
                    Recommendation = "Start the Windows Defender Firewall service and set it to Automatic startup"
                }
            }
        }
        
        Write-Host "  Analyzing wireless network configuration..." -ForegroundColor Gray
        
        if ($WirelessData -and $WirelessData.HasWirelessCapability) {
            if ($WirelessData.SecurityIssues) {
                foreach ($issue in $WirelessData.SecurityIssues) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "Wireless"
                        Title = "$($issue.Type)"
                        Severity = $issue.Severity
                        Description = $issue.Description
                        Component = "Wireless Interface: $($issue.Interface)"
                        Recommendation = "Address wireless security issue by updating configuration"
                    }
                }
            }
            
            if ($WirelessData.WirelessProfiles) {
                $insecureProfiles = $WirelessData.WirelessProfiles | Where-Object { -not $_.IsSecure }
                foreach ($profile in $insecureProfiles) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "Wireless"
                        Title = "Insecure Wireless Profile"
                        Severity = "High"
                        Description = "Wireless profile '$($profile.ProfileName)' uses insecure authentication/encryption"
                        Component = "Wireless Profile: $($profile.ProfileName)"
                        Recommendation = "Remove this profile and reconnect using WPA2 or WPA3 security"
                    }
                }
            }
        }
        

        Write-Host "  Analyzing network services..." -ForegroundColor Gray
        
        if ($NetworkServiceData) {
            if ($NetworkServiceData.CriticalServiceIssues) {
                foreach ($issue in $NetworkServiceData.CriticalServiceIssues) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "Network Services"
                        Title = "Critical Service Issue"
                        Severity = $issue.Severity
                        Description = "$($issue.Issue) (Service: $($issue.DisplayName), Status: $($issue.Status), StartType: $($issue.StartType))"
                        Component = "Service: $($issue.Name)"
                        Recommendation = $issue.Recommendation
                    }
                }
            }
            
            if ($NetworkServiceData.SuspiciousServices) {
                foreach ($service in $NetworkServiceData.SuspiciousServices) {
                    $securityFindings += [PSCustomObject]@{
                        Category = "Network Services"
                        Title = "Suspicious Service Configuration"
                        Severity = $service.Severity
                        Description = "$($service.Issue) (Service: $($service.DisplayName))"
                        Component = "Service: $($service.Name)"
                        Recommendation = $service.Recommendation
                    }
                }
            }
        }
        
        Write-Host "  Analyzing network event logs..." -ForegroundColor Gray
        
        if ($EventLogData) {
            if ($EventLogData.SuspiciousEvents) {
                $groupedEvents = $EventLogData.SuspiciousEvents | Group-Object -Property MatchDescription
                
                foreach ($group in $groupedEvents) {
                    $exampleEvent = $group.Group[0]
                    $eventTimes = $group.Group | ForEach-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") }
                    $timeRange = if ($group.Count -gt 1) {
                        "between $($eventTimes[0]) and $($eventTimes[-1])"
                    } else {
                        "at $($eventTimes[0])"
                    }
                    
                    $securityFindings += [PSCustomObject]@{
                        Category = "Event Logs"
                        Title = "Suspicious Event Detected"
                        Severity = $exampleEvent.Severity
                        Description = "$($exampleEvent.MatchDescription): $($group.Count) occurrence(s) $timeRange (EventID: $($exampleEvent.EventID), Log: $($exampleEvent.LogName))"
                        Component = "Event ID: $($exampleEvent.EventID)"
                        Recommendation = "Investigate these events for potential security issues"
                    }
                }
            }
            
            $loginFailures = $EventLogData.SecurityEvents | Where-Object { $_.EventID -eq 4625 }
            if ($loginFailures -and $loginFailures.Count -gt 10) {
                $securityFindings += [PSCustomObject]@{
                    Category = "Authentication"
                    Title = "Multiple Authentication Failures"
                    Severity = "Medium"
                    Description = "Detected $($loginFailures.Count) failed login attempts in event logs"
                    Component = "Security Events"
                    Recommendation = "Investigate potential brute force attempts"
                }
            }
            $accountLockouts = $EventLogData.SecurityEvents | Where-Object { $_.EventID -eq 4740 }
            if ($accountLockouts -and $accountLockouts.Count -gt 0) {
                $securityFindings += [PSCustomObject]@{
                    Category = "Authentication"
                    Title = "Account Lockouts Detected"
                    Severity = "Medium"
                    Description = "Detected $($accountLockouts.Count) account lockout events in logs"
                    Component = "Security Events"
                    Recommendation = "Investigate potential brute force or account compromise attempts"
                }
            }
        }
        
        Write-Host "  Generating overall network security assessment..." -ForegroundColor Gray
        $criticalFindings = $securityFindings | Where-Object { $_.Severity -eq "Critical" }
        $highFindings = $securityFindings | Where-Object { $_.Severity -eq "High" }
        $mediumFindings = $securityFindings | Where-Object { $_.Severity -eq "Medium" }
        $lowFindings = $securityFindings | Where-Object { $_.Severity -eq "Low" }
        $overallRisk = "Low"
        if ($criticalFindings.Count -gt 0) {
            $overallRisk = "Critical"
        } elseif ($highFindings.Count -gt 3) {
            $overallRisk = "High"
        } elseif ($highFindings.Count -gt 0 -or $mediumFindings.Count -gt 5) {
            $overallRisk = "Medium"
        }
        $vulnerabilities = @()
        foreach ($finding in $criticalFindings) {
            $vulnerabilities += [PSCustomObject]@{
                Severity = $finding.Severity
                Title = $finding.Title
                Description = $finding.Description
                Category = $finding.Category
                Recommendation = $finding.Recommendation
            }
        }

        foreach ($finding in $highFindings) {
            $vulnerabilities += [PSCustomObject]@{
                Severity = $finding.Severity
                Title = $finding.Title
                Description = $finding.Description
                Category = $finding.Category
                Recommendation = $finding.Recommendation
            }
        }
        
        foreach ($finding in $mediumFindings | Select-Object -First 5) {
            $vulnerabilities += [PSCustomObject]@{
                Severity = $finding.Severity
                Title = $finding.Title
                Description = $finding.Description
                Category = $finding.Category
                Recommendation = $finding.Recommendation
            }
        }
        $anomalies = @()
        if ($NetworkData -and $NetworkData.Connections -and $NetworkData.Connections.Connections) {
            $uncommonPorts = $NetworkData.Connections.Connections | 
                             Where-Object { $_.State -eq 'Listen' -and [int]$_.LocalPort -gt 10000 -and [int]$_.LocalPort -lt 65535 }
            
            if ($uncommonPorts) {
                $anomalies += [PSCustomObject]@{
                    Category = "Network Configuration"
                    Title = "Uncommon Listening Ports"
                    Description = "Detected services listening on uncommon high ports: " + (($uncommonPorts | Select-Object -First 5 | ForEach-Object { "$($_.LocalPort) ($($_.ProcessName))" }) -join ", ")
                    Significance = "May indicate non-standard applications or potentially malicious services"
                }
            }
        }
        
        if ($NetworkData -and $NetworkData.Connections -and $NetworkData.Connections.Connections) {
            $commonNetworkProcesses = @('svchost.exe', 'lsass.exe', 'System', 'services.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'outlook.exe')
            $unusualProcesses = $NetworkData.Connections.Connections | 
                                Where-Object { $_.ProcessName -and -not ($commonNetworkProcesses -contains $_.ProcessName) } |
                                Group-Object -Property ProcessName
            
            if ($unusualProcesses) {
                $anomalies += [PSCustomObject]@{
                    Category = "Network Activity"
                    Title = "Unusual Processes with Network Activity"
                    Description = "Detected uncommon processes with network activity: " + (($unusualProcesses | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count) connections)" }) -join ", ")
                    Significance = "May indicate unexpected network usage by applications"
                }
            }
        }

        if ($FirewallData -and $FirewallData.ServiceStatus -ne "Running" -and $NetworkServiceData -and $NetworkServiceData.SecurityProducts) {
            if ($NetworkServiceData.SecurityProducts.Count -eq 0) {
                $anomalies += [PSCustomObject]@{
                    Category = "Firewall"
                    Title = "No Active Firewall Detected"
                    Description = "Windows Firewall is disabled but no third-party security products were detected"
                    Significance = "System may be operating without firewall protection"
                }
            }
        }

        $recommendations = @()
        if ($criticalFindings.Count -gt 0 -or $highFindings.Count -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = "High"
                Title = "Address Critical and High Severity Findings"
                Description = "Immediately address all critical and high severity findings as they represent significant security risks"
                Implementation = "Follow the specific recommendations for each finding"
            }
        }
        if ($FirewallData) {
            if ($FirewallData.ServiceStatus -ne "Running" -or ($FirewallData.Profiles | Where-Object { -not $_.Enabled }).Count -gt 0) {
                $recommendations += [PSCustomObject]@{
                    Priority = "High"
                    Title = "Enable Windows Firewall"
                    Description = "Ensure Windows Firewall is enabled and running for all profiles"
                    Implementation = "Enable Windows Firewall via Control Panel or Group Policy"
                }
            }
            
            if ($FirewallData.SuspiciousRules -and $FirewallData.SuspiciousRules.Count -gt 0) {
                $recommendations += [PSCustomObject]@{
                    Priority = "Medium"
                    Title = "Review Suspicious Firewall Rules"
                    Description = "Review and clean up potentially dangerous firewall rules"
                    Implementation = "Use Windows Defender Firewall with Advanced Security to inspect and remove suspicious rules"
                }
            }
        }
        if ($WirelessData -and $WirelessData.HasWirelessCapability -and $WirelessData.SecurityIssues -and $WirelessData.SecurityIssues.Count -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = "Medium"
                Title = "Address Wireless Security Issues"
                Description = "Address identified wireless security issues to prevent unauthorized access"
                Implementation = "Update wireless configurations, remove insecure profiles, and ensure WPA2/WPA3 security is used"
            }
        }
        if ($NetworkServiceData -and $NetworkServiceData.CriticalServiceIssues -and $NetworkServiceData.CriticalServiceIssues.Count -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = "Medium"
                Title = "Restore Critical Network Services"
                Description = "Ensure all critical network services are properly configured and running"
                Implementation = "Start required services and configure them to start automatically"
            }
        }
        if ($EventLogData -and $EventLogData.SuspiciousEvents -and $EventLogData.SuspiciousEvents.Count -gt 5) {
            $recommendations += [PSCustomObject]@{
                Priority = "Medium"
                Title = "Investigate Suspicious Network Activity"
                Description = "Investigate system for potential compromise based on suspicious events"
                Implementation = "Perform deeper investigation using the identified suspicious events as starting points"
            }
        }
        if ($securityFindings | Where-Object { $_.Category -eq "Network Exposure" -and $_.Severity -eq "High" }) {
            $recommendations += [PSCustomObject]@{
                Priority = "High"
                Title = "Reduce Network Attack Surface"
                Description = "Minimize exposed network services to reduce attack surface"
                Implementation = "Close unnecessary ports, disable unneeded services, and restrict access to required services using firewall rules"
            }
        }
        $securityMetrics = @{
            RiskScore = switch ($overallRisk) {
                "Critical" { 80 + [Math]::Min($criticalFindings.Count * 5, 20) }
                "High" { 60 + [Math]::Min($highFindings.Count * 4, 20) }
                "Medium" { 40 + [Math]::Min($mediumFindings.Count * 2, 20) }
                "Low" { 20 + [Math]::Min($lowFindings.Count, 20) }
                default { 10 }
            }
            NetworkExposure = if ($NetworkData -and $NetworkData.Connections) {
                $listeners = $NetworkData.Connections.Connections | Where-Object { $_.State -eq 'Listen' -and $_.LocalAddress -eq '0.0.0.0' }
                $listeners.Count
            } else { 0 }
            
            PublicShares = if ($NetworkData -and $NetworkData.NetworkShareInformation) {
                $NetworkData.NetworkShareInformation.NonSystemShares
            } else { 0 }
            
            FirewallStatus = if ($FirewallData) {
                if (($FirewallData.Profiles | Where-Object { -not $_.Enabled }).Count -gt 0) {
                    "Partial"
                } elseif ($FirewallData.ServiceStatus -ne "Running") {
                    "Disabled"
                } else {
                    "Enabled"
                }
            } else { "Unknown" }
            
            SuspiciousFindings = $criticalFindings.Count + $highFindings.Count 
            AssessmentDate = Get-Date
            SystemName = $env:COMPUTERNAME
            SecurityRating = $overallRisk
        }

        $result = [PSCustomObject]@{
            SecurityFindings = $securityFindings
            TopVulnerabilities = $vulnerabilities
            Anomalies = $anomalies
            Recommendations = $recommendations
            SecurityMetrics = $securityMetrics
            OverallRisk = $overallRisk
            FindingsBySeverity = [PSCustomObject]@{
                Critical = $criticalFindings.Count
                High = $highFindings.Count
                Medium = $mediumFindings.Count
                Low = $lowFindings.Count
                Total = $securityFindings.Count
            }
            FindingsByCategory = $securityFindings | Group-Object -Property Category | ForEach-Object {
                [PSCustomObject]@{
                    Category = $_.Name
                    Count = $_.Count
                    Findings = $_.Group
                }
            }
        }
        
        Write-Host "  Identified $($securityFindings.Count) security findings ($($criticalFindings.Count) critical, $($highFindings.Count) high, $($mediumFindings.Count) medium, $($lowFindings.Count) low)." -ForegroundColor $(if ($criticalFindings.Count -gt 0) { "Red" } elseif ($highFindings.Count -gt 0) { "Yellow" } else { "Green" })
        Write-Host "  Overall network security risk assessment: $overallRisk" -ForegroundColor $(switch ($overallRisk) {
            "Critical" { "Red" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
            default { "Gray" }
        })
        Write-Host "  Generated $($recommendations.Count) specific security recommendations." -ForegroundColor Cyan
        
        Write-Log -Message "Completed network security analysis: $($securityFindings.Count) findings, overall risk: $overallRisk" -Level "Success"
        return $result
    }
    catch {
        Write-Log -Message "Error performing network security analysis: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error performing network security analysis: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}



function Main {
    Write-Host "`n========================= Network Collection Started =========================" -ForegroundColor Cyan
    Write-Host "Collection Time: $(Get-Date)" -ForegroundColor Cyan
    Write-Host "Computer Name: $ComputerName" -ForegroundColor Cyan
    Write-Host "Output Path: $OutputPath" -ForegroundColor Cyan
    Write-Host "Quick Scan Mode: $QuickScan" -ForegroundColor Cyan
    Write-Host "Selected Modules: $($ModuleFlags -join ', ')" -ForegroundColor Cyan
    Write-Host "=======================================================================" -ForegroundColor Cyan
    
    if (-not (Initialize-OutputLocation)) {
        Write-Error "Failed to initialize output location. Exiting."
        return
    }
    
    $isAdmin = Test-AdminPrivileges
    if (-not $isAdmin) {
        Write-Host "`nWARNING: Running without administrator privileges. Some information may be limited." -ForegroundColor Yellow
        Write-Log -Message "Running without administrator privileges. Some information may be limited." -Level "Warning"
    }
    $collectionResults = @{}
    $moduleCount = 0
    $enabledModules = 0
    $runInterfaces = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Interfaces"
    $runConnections = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Connections"
    $runRouting = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Routing"
    $runDNS = $ModuleFlags -contains "All" -or $ModuleFlags -contains "DNS"
    $runShares = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Shares"
    $runFirewall = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Firewall"
    $runWireless = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Wireless"
    $runServices = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Services"
    $runEventLogs = $ModuleFlags -contains "All" -or $ModuleFlags -contains "EventLogs"
    $runSecurity = $ModuleFlags -contains "All" -or $ModuleFlags -contains "Security"
    $enabledModules = @($runInterfaces, $runConnections, $runRouting, $runDNS, $runShares, 
                         $runFirewall, $runWireless, $runServices, $runEventLogs, $runSecurity).Where({$_ -eq $true}).Count
    

    if ($runInterfaces) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Network Interface Information" -ForegroundColor Yellow
        $interfaces = Get-NetworkInterfaces
        $collectionResults.Interfaces = $interfaces
        Write-Host "Exporting network interface information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $interfaces -FilePath $InterfacesOutputPath
    }

    if ($runConnections) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Network Connection Information" -ForegroundColor Yellow
        $connections = Get-NetworkConnections
        $collectionResults.Connections = $connections
        Write-Host "Exporting network connection information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $connections -FilePath $ConnectionsOutputPath
    }
    if ($runRouting) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Routing Information" -ForegroundColor Yellow
        $routing = Get-RoutingInformation
        $collectionResults.RoutingInformation = $routing
        Write-Host "Exporting routing information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $routing -FilePath $RoutingOutputPath
    }
    if ($runDNS) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting DNS Cache Information" -ForegroundColor Yellow
        $dnsCache = Get-DNSCacheInformation
        $collectionResults.DNSCacheInformation = $dnsCache
        Write-Host "Exporting DNS cache information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $dnsCache -FilePath $DNSCacheOutputPath
    }

    if ($runShares -and -not $QuickScan) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Network Share Information" -ForegroundColor Yellow
        $shares = Get-NetworkShareInformation
        $collectionResults.NetworkShareInformation = $shares
        Write-Host "Exporting network share information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $shares -FilePath $NetworkSharesOutputPath
    }
    elseif ($runShares -and $QuickScan) {
        Write-Host "`n[$moduleCount/$enabledModules] Skipping Network Share Collection (Quick Scan enabled)" -ForegroundColor DarkGray
        $collectionResults.NetworkShareInformation = $null
    }

    if ($runFirewall) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Firewall Configuration" -ForegroundColor Yellow
        $firewall = Get-FirewallConfiguration -QuickScan:$QuickScan
        $collectionResults.FirewallConfiguration = $firewall
        Write-Host "Exporting firewall configuration to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $firewall -FilePath $FirewallOutputPath
    }
    if ($runWireless) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Wireless Network Information" -ForegroundColor Yellow
        $wireless = Get-WirelessNetworkInformation -QuickScan:$QuickScan
        $collectionResults.WirelessNetworkInformation = $wireless
        Write-Host "Exporting wireless network information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $wireless -FilePath $WirelessOutputPath
    }
    if ($runServices) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Network Service Information" -ForegroundColor Yellow
        $services = Get-NetworkServiceInformation -QuickScan:$QuickScan
        $collectionResults.NetworkServiceInformation = $services
        Write-Host "Exporting network service information to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $services -FilePath $NetworkServicesOutputPath
    }
    if ($runEventLogs) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Collecting Network Event Logs" -ForegroundColor Yellow
        $daysBack = if ($QuickScan) { 1 } else { 7 }
        $maxEvents = if ($QuickScan) { 200 } else { 1000 }
        
        $eventLogs = Get-NetworkEventLogs -QuickScan:$QuickScan -DaysBack $daysBack -MaxEvents $maxEvents
        $collectionResults.NetworkEventLogs = $eventLogs
        Write-Host "Exporting network event logs to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $eventLogs -FilePath $EventLogsOutputPath
    }
    
    if ($runSecurity) {
        $moduleCount++
        Write-Host "`n[$moduleCount/$enabledModules] Performing Network Security Analysis" -ForegroundColor Yellow
        $securityAnalysis = Get-NetworkSecurityAnalysis -QuickScan:$QuickScan `
                            -NetworkData $collectionResults `
                            -FirewallData $collectionResults.FirewallConfiguration `
                            -WirelessData $collectionResults.WirelessNetworkInformation `
                            -NetworkServiceData $collectionResults.NetworkServiceInformation `
                            -EventLogData $collectionResults.NetworkEventLogs
        
        $collectionResults.NetworkSecurityAnalysis = $securityAnalysis
        Write-Host "Exporting network security analysis to JSON..." -ForegroundColor Gray
        Export-ToJson -InputObject $securityAnalysis -FilePath $SecurityAnalysisOutputPath
    }
    
    Write-Host "`nGenerating collection summary..." -ForegroundColor Cyan
    $summary = [PSCustomObject]@{
        CollectionTime = Get-Date
        ComputerName = $ComputerName
        RunAsAdmin = $isAdmin
        QuickScan = $QuickScan
        EnabledModules = $ModuleFlags
        FilterOptions = $FilterOptions
    }

    if ($collectionResults.Interfaces) {
        $summary | Add-Member -MemberType NoteProperty -Name "Interfaces" -Value @{
            TotalInterfaces = $collectionResults.Interfaces.Count
            ActiveInterfaces = ($collectionResults.Interfaces | Where-Object { $_.Status -eq "Up" }).Count
        }
    }
    
    if ($collectionResults.Connections) {
        $summary | Add-Member -MemberType NoteProperty -Name "Connections" -Value @{
            TotalConnections = $collectionResults.Connections.TotalConnections
            TotalListeners = $collectionResults.Connections.TotalListeners
        }
    }
    
    if ($collectionResults.RoutingInformation) {
        $summary | Add-Member -MemberType NoteProperty -Name "RoutingInformation" -Value @{
            RouteCount = $collectionResults.RoutingInformation.RouteCount
            ARPEntries = $collectionResults.RoutingInformation.ARPEntries.Count
        }
    }
    
    if ($collectionResults.DNSCacheInformation) {
        $summary | Add-Member -MemberType NoteProperty -Name "DNSCacheInformation" -Value @{
            CacheEntries = $collectionResults.DNSCacheInformation.TotalCacheEntries
            HostsFileEntries = $collectionResults.DNSCacheInformation.TotalHostsEntries
        }
    }
    
    if ($collectionResults.NetworkShareInformation) {
        $summary | Add-Member -MemberType NoteProperty -Name "NetworkShareInformation" -Value @{
            TotalShares = $collectionResults.NetworkShareInformation.TotalShares
            NonSystemShares = $collectionResults.NetworkShareInformation.NonSystemShares
            ConnectedDrives = $collectionResults.NetworkShareInformation.TotalConnectedDrives
        }
    }
    
    if ($collectionResults.FirewallConfiguration) {
        $summary | Add-Member -MemberType NoteProperty -Name "FirewallConfiguration" -Value @{
            FirewallEnabled = $collectionResults.FirewallConfiguration.FirewallEnabled
            TotalRules = $collectionResults.FirewallConfiguration.TotalRules
            EnabledRules = $collectionResults.FirewallConfiguration.EnabledRules
            SuspiciousRules = $collectionResults.FirewallConfiguration.SuspiciousRuleCount
        }
    }
    
    if ($collectionResults.WirelessNetworkInformation) {
        $summary | Add-Member -MemberType NoteProperty -Name "WirelessNetworkInformation" -Value @{
            HasWireless = $collectionResults.WirelessNetworkInformation.HasWirelessCapability
            Interfaces = $collectionResults.WirelessNetworkInformation.TotalInterfaces
            Profiles = $collectionResults.WirelessNetworkInformation.TotalProfiles
            SecurityIssues = $collectionResults.WirelessNetworkInformation.SecurityIssueCount
        }
    }
    
    if ($collectionResults.NetworkServiceInformation) {
        $summary | Add-Member -MemberType NoteProperty -Name "NetworkServiceInformation" -Value @{
            Services = $collectionResults.NetworkServiceInformation.TotalNetworkServices
            CriticalIssues = $collectionResults.NetworkServiceInformation.CriticalIssues
            SuspiciousServices = $collectionResults.NetworkServiceInformation.SuspiciousIssuesCount
        }
    }
    
    if ($collectionResults.NetworkEventLogs) {
        $summary | Add-Member -MemberType NoteProperty -Name "NetworkEventLogs" -Value @{
            TotalEvents = $collectionResults.NetworkEventLogs.TotalEventsCollected
            SuspiciousEvents = $collectionResults.NetworkEventLogs.TotalSuspiciousEvents
            TimeRange = "$($collectionResults.NetworkEventLogs.TimeRange.DaysBack) days"
        }
    }
    
    if ($collectionResults.NetworkSecurityAnalysis) {
        $summary | Add-Member -MemberType NoteProperty -Name "NetworkSecurityAnalysis" -Value @{
            OverallRisk = $collectionResults.NetworkSecurityAnalysis.OverallRisk
            TotalFindings = $collectionResults.NetworkSecurityAnalysis.FindingsBySeverity.Total
            CriticalFindings = $collectionResults.NetworkSecurityAnalysis.FindingsBySeverity.Critical
            HighFindings = $collectionResults.NetworkSecurityAnalysis.FindingsBySeverity.High
            RiskScore = $collectionResults.NetworkSecurityAnalysis.SecurityMetrics.RiskScore
        }
    }
    
    Export-ToJson -InputObject $summary -FilePath $SummaryOutputPath
    Write-Host "`n========================= Collection Summary =========================" -ForegroundColor Green
    if ($collectionResults.Interfaces) {
        Write-Host "Interfaces: $($summary.Interfaces.TotalInterfaces) total ($($summary.Interfaces.ActiveInterfaces) active)" -ForegroundColor White
    }
    
    if ($collectionResults.Connections) {
        Write-Host "Connections: $($summary.Connections.TotalConnections) total ($($summary.Connections.TotalListeners) listeners)" -ForegroundColor White
    }
    
    if ($collectionResults.RoutingInformation) {
        Write-Host "Routes: $($summary.RoutingInformation.RouteCount) total ($($summary.RoutingInformation.ARPEntries) ARP entries)" -ForegroundColor White
    }
    
    if ($collectionResults.DNSCacheInformation) {
        Write-Host "DNS Cache: $($summary.DNSCacheInformation.CacheEntries) cache entries, $($summary.DNSCacheInformation.HostsFileEntries) hosts file entries" -ForegroundColor White
    }
    
    if ($collectionResults.NetworkShareInformation) {
        Write-Host "Shares: $($summary.NetworkShareInformation.TotalShares) total ($($summary.NetworkShareInformation.NonSystemShares) non-system, $($summary.NetworkShareInformation.ConnectedDrives) connected drives)" -ForegroundColor White
    }
    if ($collectionResults.FirewallConfiguration) {
        $firewallStatus = if ($summary.FirewallConfiguration.FirewallEnabled) { "Enabled" } else { "Disabled" }
        Write-Host "Firewall: $firewallStatus, $($summary.FirewallConfiguration.TotalRules) total rules ($($summary.FirewallConfiguration.SuspiciousRules) suspicious)" -ForegroundColor White
    }
    
    if ($collectionResults.WirelessNetworkInformation -and $collectionResults.WirelessNetworkInformation.HasWirelessCapability) {
        Write-Host "Wireless: $($summary.WirelessNetworkInformation.Profiles) profiles, $($summary.WirelessNetworkInformation.SecurityIssues) security issues" -ForegroundColor White
    }
    
    if ($collectionResults.NetworkServiceInformation) {
        Write-Host "Network Services: $($summary.NetworkServiceInformation.Services) services, $($summary.NetworkServiceInformation.CriticalIssues) critical issues, $($summary.NetworkServiceInformation.SuspiciousServices) suspicious" -ForegroundColor White
    }
    
    if ($collectionResults.NetworkEventLogs) {
        Write-Host "Event Logs: $($summary.NetworkEventLogs.TotalEvents) relevant events, $($summary.NetworkEventLogs.SuspiciousEvents) suspicious events (past $($summary.NetworkEventLogs.TimeRange))" -ForegroundColor White
    }
    
    if ($collectionResults.NetworkSecurityAnalysis) {
        $riskColor = switch ($summary.NetworkSecurityAnalysis.OverallRisk) {
            "Critical" { "Red" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
            default { "White" }
        }
        Write-Host "Security Analysis: Overall Risk - $($summary.NetworkSecurityAnalysis.OverallRisk), $($summary.NetworkSecurityAnalysis.TotalFindings) findings" -ForegroundColor $riskColor
    }
    
    Write-Host "Results saved to: $OutputPath" -ForegroundColor White
    Write-Host "===================================================================" -ForegroundColor Green
    
    Write-Log -Message "Network collection completed successfully" -Level "Success"
    Write-Log -Message "Results saved to $OutputPath" -Level "Success"
    
    return $summary
}

Main

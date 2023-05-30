# Check Active Directory Server Health Script 
##Variables
$InactiveDays = 90
$Days = (Get-Date).Adddays(-($InactiveDays))

##DCDiag Function
function Invoke-DcDiag {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController
    )
    $result = dcdiag /s:$DomainController
    $result | select-string -pattern '\. (.*) \b(passed|failed)\b test (.*)' | ForEach-Object {
        $obj = @{
            TestName = $_.Matches.Groups[3].Value
            TestResult = $_.Matches.Groups[2].Value
            Entity = $_.Matches.Groups[1].Value
        }
        [pscustomobject]$obj
    }
}

##Sites Function
function Get-SitesInfo {
    ## Get all replication subnets from Sites & Services
    $Subnets = Get-ADReplicationSubnet -filter * -Properties * | Select-Object Name, Site, Location, Description

    ## Create an empty array to build the subnet list
    $SiteResultsArray = @()

    ## Loop through all subnets and build the list
    ForEach ($Subnet in $Subnets) {
        
        $SiteName = ""
        If ($null -ne $Subnet.Site) { $SiteName = $Subnet.Site.Split(',')[0].Trim('CN=') }

        $DcInSite = $False
        If ($DcList.Site -Contains $SiteName) { $DcInSite = $True }
        
        $RA = New-Object PSObject
        $RA | Add-Member -type NoteProperty -name "Subnet"   -Value $Subnet.Name
        $RA | Add-Member -type NoteProperty -name "SiteName" -Value $SiteName
        $RA | Add-Member -type NoteProperty -name "DcInSite" -Value $DcInSite
        $RA | Add-Member -type NoteProperty -name "SiteLoc"  -Value $Subnet.Location
        $RA | Add-Member -type NoteProperty -name "SiteDesc" -Value $Subnet.Description
        
        $SiteResultsArray += $RA

}

$SiteResultsArray
}

##Remaining RIDs Function
function Get-RIDsremainingAdPsh
{

    param ($domainDN)
    $property = get-adobject "cn=rid manager$,cn=system,$domainDN" -property ridavailablepool -server ((Get-ADDomain $domaindn).RidMaster)
    $rid = $property.ridavailablepool    
    [int32]$totalSIDS = $($rid) / ([math]::Pow(2,32))
    [int64]$temp64val = $totalSIDS * ([math]::Pow(2,32))
    [int32]$currentRIDPoolCount = $($rid) - $temp64val
    $ridsremaining = $totalSIDS - $currentRIDPoolCount

    $Rid = New-Object PSObject
    $Rid | Add-Member -type NoteProperty -name "IssuedRID"  -Value $currentRIDPoolCount
    $Rid | Add-Member -type NoteProperty -name "RemainingRID" -Value $ridsremaining
    
    $RIDsResultsArray += $Rid
    $RIDsResultsArray
}

##Duplicate SPN Detection
Function Get-DuplicateSPN
{
$spncmd="setspn -X -p"
$SPNOut = Invoke-Expression $spncmd
$SPNres = $SPNOut.Where({ $_ -ne "" })
$SPNres[1]
}

#Check if virtual
$IsVirtual = ((Get-WmiObject win32_computersystem).model -like 'VMware*' -or ((Get-WmiObject win32_computersystem).model -eq 'Virtual Machine') -or ((Get-WmiObject win32_computersystem).model -like 'Standard PC*'))
if ($IsVirtual -eq "True") {
    Write-Host "This is a virtual server" -ForegroundColor Green
} else {
    Write-Host "This is a phyiscal server" -ForegroundColor Yellow
}

#Hostname Printout
write-host "Hostname is"$env:COMPUTERNAME -ForegroundColor Green

# Check if the Active Directory module is available 

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { 

    Write-Host "Active Directory module not found. Please make sure the Remote Server Administration Tools (RSAT) are installed." -ForegroundColor Red 

    exit 1 

} else {
    # Import the Active Directory module
    Import-Module ActiveDirectory
}

  

# Check if running with administrative privileges 

$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent() 

$principal = New-Object Security.Principal.WindowsPrincipal($currentUser) 

if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) { 

    Write-Host "This script needs to be run with administrative privileges." -ForegroundColor Red 

    exit 1 

} 

  

# Check domain controller connectivity 

$domainControllers = Get-ADDomainController -Filter * 

$healthyControllers = $domainControllers | Where-Object { 

    $result = Test-Connection -ComputerName $_.HostName -Count 2 -Quiet 

    if (-not $result) { 

        Write-Host "Domain controller $($_.HostName) is not reachable." -ForegroundColor Yellow 

    } 

    $result 

} 

  

# Check replication status 

Write-Host "Checking replication status..." 

$replicationStatus = Get-ADReplicationPartnerMetadata -Target $healthyControllers.Domain -Scope Domain -ErrorAction SilentlyContinue 

if ($healthyControllers.count -gt 1 ) {

    if ($replicationStatus) { 

        $replicationStatus | ForEach-Object { 

            if ($_.LastReplicationResult -ne 0) { 

                Write-Host "Replication issue detected with partner $($_.Partner) on $($_.LastReplicationTime).`n" -ForegroundColor Red 

            } 

        } 

    } else { 

        Write-Host "Failed to retrieve replication partner metadata.`n" -ForegroundColor Yellow 

    } 
} else { 

    Write-Host "There is only one DC in the domain skipping test`n" -ForegroundColor DarkGreen

} 

#Run a DC Diag Locally  
$LocalDCDiag = Invoke-DcDiag -DomainController $env:COMPUTERNAME

foreach ($item in $LocalDCDiag) {
    if ($item.TestResult -like '*failed*') {
        Write-Host "Test $($item.TestName) Failed" -ForegroundColor Red
    }
}


# Check domain functional level 

$domain = Get-ADDomain 

$domainFunctionalLevel = $domain.DomainMode 

Write-Host "`nDomain functional level: "  -NoNewline
Write-Host "$domainFunctionalLevel"   -ForegroundColor Blue

  

# Check forest functional level 

$forest = Get-ADForest 

$forestFunctionalLevel = $forest.ForestMode 

Write-Host "`nForest functional level: "  -NoNewline
Write-Host "$forestFunctionalLevel `n"   -ForegroundColor Blue

  

# Check FSMO role holders 

$domainNamingMaster = (Get-ADDomainController -Filter { OperationMasterRoles -like "*DomainNamingMaster*" }).HostName
$schemaMaster = (Get-ADDomainController -Filter { OperationMasterRoles -like "*SchemaMaster*" }).HostName
$ridMaster = (Get-ADDomainController -Filter { OperationMasterRoles -like "*RIDMaster*" }).HostName
$pdcEmulator = (Get-ADDomainController -Filter { OperationMasterRoles -like "*PDCEmulator*" }).HostName
$infrastructureMaster = (Get-ADDomainController -Filter { OperationMasterRoles -like "*InfrastructureMaster*" }).HostName

# Display the names of the servers hosting the FSMO roles
Write-Host "Domain Naming Master: " -NoNewline
Write-Host "$domainNamingMaster" -ForegroundColor Blue
Write-Host "Schema Master: " -NoNewline
Write-Host "$schemaMaster" -ForegroundColor Blue
Write-Host "RID Master: " -NoNewline
Write-Host "$ridMaster" -ForegroundColor Blue
Write-Host "PDC Emulator: " -NoNewline
Write-Host "$pdcEmulator" -ForegroundColor Blue
Write-Host "Infrastructure Master: " -NoNewline
Write-Host "$infrastructureMaster`n" -ForegroundColor Blue

# Retrieve all AD sites
$Siteinfo = Get-SitesInfo

foreach ($sitename in $Siteinfo.SiteName) {
    $ErrorActionPreference = "SilentlyContinue"
    try {
        $hosts = Get-ADDomainController -Discover -Site $sitename
        foreach ($server in $hosts.HostName) {
            try {
                $dnsResolution = Test-Connection -ComputerName $server -Count 1 -Quiet
        
                if ($dnsResolution) {
                    $135result = Test-NetConnection -ComputerName $server -Port 135 -InformationLevel Quiet
                    if ($135result) {
                        Write-Host "Port 135 is open on $server" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Port 135 is closed on $server" -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "DNS resolution failed for $server" -ForegroundColor Red
                }
            }
            catch {
                Write-Host "An error occurred while testing DNS resolution of $server"
            }
        }
    }
        catch {
            Write-Host "Error while getting Domain controlers for site $sitename"
        }
    }

# Find Stale AD Users
$OutdatedUser = Get-ADUser -Filter {LastLogonTimeStamp -lt $Days -and enabled -eq $true} -Properties LastLogonTimeStamp
Write-host "`nThere are"$OutdatedUser.count"Uses who have not logged in in the last $InactiveDays days`n"

#Find Unlinked GPO items
$UnlinkedGPO = Get-GPO -All | Sort-Object displayname | Where-Object { If ( $_ | Get-GPOReport -ReportType XML | Select-String -NotMatch "<LinksTo>" ) {$_.DisplayName } }
Write-host "There are"$UnlinkedGPO.count" unlinked GPO see names below"
$UnlinkedGPO.DisplayName

#Remaining RID's
$Rids = Get-RIDsRemainingAdPsh $domain.DistinguishedName
Write-host "`nThere are" $Rids.IssuedRID "Issued and" $Rids.RemainingRID "Rids remaining"

#DuplicateSPN check
$SPNResult = Get-DuplicateSPN
Write-Host "`nWe"$SPNResult"`n"

#Display time server source 
$Timesource = Invoke-Expression "w32tm /query /computer:$computers /source"
if ($IsVirtual -eq "True") {
    if ($Timesource -like "*Local*") {
        Write-Host "This servers time source is" $Timesource "and this is a VM so check hypervisor time settings`n" -ForegroundColor Yellow
    }
    elseif ($Timesource -like "*Free-running*") {
        Write-Host "This servers time source is" $Timesource "and this is a VM so check hypervisor time settings`n" -ForegroundColor Yellow
    }
} else {
    Write-Host "This servers time source is" $Timesource"`n" -ForegroundColor Green
}

#DNS Check
$DnsServerScavenging = Get-DnsServerScavenging
if ($DnsServerScavenging.ScavengingState -eq "True") {
    Write-Host "DNS reccord scavenging is enabled and set to" $DnsServerScavenging.ScavengingInterval -ForegroundColor Green
} else {
    Write-Host "DNS reccord scavenging is disabled" -ForegroundColor Red
}

#Get DNS Forwarders
$DNSFWD = Get-DnsServerForwarder
if ($DNSFWD.IPAddress.count -gt 1) {
    foreach ($DNSSVR in $DNSFWD.IPAddress) {
    Write-Host "DNS forwarder is set to" $DNSSVR
}
}
else {
    Write-host "Only one DNS forwarder is configured" -ForegroundColor Red
}

#Checking PasswordNotRequired
$NoPassReq = Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties *
Write-host "`nBelow are accounts with the attribute PasswordNotRequired set:"
foreach ($user in $NoPassReq){
    Write-Host $user.name -ForegroundColor Red
}

#Checking PasswordNeverExpires
$NoPassReq = get-aduser -filter * -properties Name, PasswordNeverExpires | Where-Object {$_.passwordNeverExpires -eq "true" }
Write-host "`nBelow are accounts with the attribute PasswordNeverExpires set:"
foreach ($user in $NoPassReq){
    Write-Host $user.name -ForegroundColor Red
}

#User Account Totals
$TotalAccounts = (Get-AdUser -filter *).count
$EnabledAccounts = (Get-AdUser -filter * |Where-Object {$_.enabled -eq "True"}).count
$DisabeldAccounts = (Get-ADUser -filter * |Where-Object {$_.enabled -ne "False"}).count
Write-host "`nThere are" $TotalAccounts "Total accounts of that" $EnabledAccounts "are enabled and" $DisabeldAccounts "Disabled`n"

#Servers Total
$ADServers = Get-ADComputer -Filter "OperatingSystem -Like '*Windows Server*'"
$StaleServers = Get-ADComputer -Filter "OperatingSystem -Like '*Windows Server*'" -Properties *
$StaleServers = $StaleServers | Where-Object {($_.LastLogonTimeStamp -lt $Days.TotalSeconds)}
Write-host "`nThere are" ($ADServers | Measure-Object).Count "servers in Active Directory and" ($StaleServers | Measure-Object).count "are stale server accounts"
if (($StaleServers | Measure-Object).Count -gt 0) {
    foreach ($Svrname in $StaleServers) {
        Write-Host $Svrname.name"is stale"
    }
}

#Workstations Total
$ADWorkstations = Get-ADComputer -Filter "OperatingSystem -notLike '*Windows Server*'"
$StaleWorkstations = Get-ADComputer -Filter "OperatingSystem -notLike '*Windows Server*'"
$StaleWorkstations = $StaleWorkstations | Where-Object {($_.LastLogonTimeStamp -lt $Days.TotalSeconds)}
Write-host "`nThere are" ($ADWorkstations | Measure-Object).Count "Workstations in Active Directory and" $StaleWorkstations.count "are stale accounts"
if (($StaleServers | Measure-Object).Count -gt 0) {
    foreach ($Svrname in $StaleServers) {
        Write-Host $Svrname.name"is stale"
    }
}

Write-Host "`n"
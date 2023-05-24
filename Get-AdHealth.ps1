# Check Active Directory Health Script 

##DCDiag Function
function Invoke-DcDiag {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController
    )
    $result = dcdiag /s:$DomainController
    $result | select-string -pattern '\. (.*) \b(passed|failed)\b test (.*)' | foreach {
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
    $Subnets = Get-ADReplicationSubnet -filter * -Properties * | Select Name, Site, Location, Description

    ## Create an empty array to build the subnet list
    $SiteResultsArray = @()

    ## Loop through all subnets and build the list
    ForEach ($Subnet in $Subnets) {
        
        $SiteName = ""
        If ($Subnet.Site -ne $null) { $SiteName = $Subnet.Site.Split(',')[0].Trim('CN=') }

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

    Write-Host "There is only one DC in the domain`n" -ForegroundColor Yellow 

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
Write-Host "$infrastructureMaster" -ForegroundColor Blue

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
<#
.SYNOPSIS
    Find weak passwords
.DESCRIPTION
    Hammers on AD to shake loose crappy passwords
    Requires https://github.com/MichaelGrafnetter/DSInternals to run - Install: Install-Module DSInternals -Force
    Or use chocolatey to install 
.EXAMPLE
    C:\PS> ./resetPassword.ps1 -h [hashfile]
    C:\PS> ./resetPassword.ps1 -w [wordlist]
    C:\PS> ./resetPassword.ps1 -bpw - this will attempt to download berzerk0's probable passwords from github and use as wordlist
    <Description of example>
.NOTES
    Author: See contributors
    Date:   COVID-19 period, 2020
#>
param(
   [Parameter(Mandatory=$true)]
   [String]$server
  ,[String]$hashList
  ,[String]$wordList
  ,[Switch]$bpw
  ,[Switch]$generateHashesFromWordList
)
cls
$berzerk0target = "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top304Thousand-probable-v2.txt"
$pathOfScript = Split-Path $MyInvocation.MyCommand.Path -Parent

$distinguishedName = (Get-ADDomain).distinguishedName

if([String]::isNullOrEmpty($distinguishedName)) {
    Write-Output "Hmm, not member of the domain??"
    exit
}

if (!$PSBoundParameters.ContainsKey('hashList') -and !$PSBoundParameters.ContainsKey('wordList') -and !$PSBoundParameters.ContainsKey('bpw')) {
    Write-Output "Well that is great an all, but we are going to need some more input..."
    Write-Output "Specify at least either -w [wordlist] / -h [hashlist] or -bpw`n"
    # Probably a pretty stupid way to do this...
    Get-Help $MyInvocation.MyCommand.Path
    #exit
}
if ($PSBoundParameters.ContainsKey('bpw')) {
    if($bpw) {
        $output = "$pathOfScript\berzerk0"
        $ext = ".txt"
        # Implement check for write access to current working dir / or scriptpath...
        (New-Object System.Net.WebClient).DownloadFile($berzerk0target, "$output$ext")
        if($PSBoundParameters.ContainsKey('generateHashesFromWordList') -and $generateHashesFromWordList) {
            Write-Output "Generating hashlist from wordlist.... is can take forever because of my lousy implementation"
            $hashListToGenerate = "$($output)_hashed$($ext)"
            foreach($line in Get-Content "$output$ext") {
                Add-Content $hashListToGenerate "$(calcNTHash($line))`n"
            }
            Write-Output "Done, now run the command with: -hashlist $hashListToGenerate parameter"
            exit
        }
        runCheckAgainstServer $server $distinguishedName $output
    }
    exit
}
if ($PSBoundParameters.ContainsKey('wordList')) {
    if($wordList) {
        runCheckAgainstServer $server $distinguishedName $wordList
    }
    exit
}
if ($PSBoundParameters.ContainsKey('hashList')) {
    if($hashList) {
        runCheckAgainstServer $server $distinguishedName $hashList $false
    }
    exit
}

function stringToSecureString($password) {
    return ConvertTo-SecureString -String $password -AsPlainText -Force
}
function calcLMHash($password) {
    return stringToSecureString($password) | ConvertTo-LMHash 
}
function calcNTHash($password) {
    return stringToSecureString($password) | ConvertTo-NTHash 
}
function resetPassword($username) {
    # temppassword should really not be static, but I want to go to bed now
    # Allow for optional reset to a new password. Might be a problem blocking people from accessing their account and reading their email 
    # Probably want to remove the part below before it uses randomized passwords. 
	$tempPassword = ConvertTo-SecureString -String "walkingsoftwareblueelephant1!" -AsPlainText -Force
	Set-ADAccountPassword -Identity $username -Reset -NewPassword $tempPassword
    $interestingBits = Get-ADUser -Identity $username -properties PasswordNeverExpires,Enabled
    if($interestingBits.PasswordNeverExpires) {
        write-host -ForeGroundColor Yellow "`t`t`tWTF!? Password is set to never expire - we'll fix that too" # Or should we??
    }
    if(!$interestingBits.Enabled) {
        write-host -ForeGroundColor Green "`t`t`tPHEW! Seems user is disabled... or, at least his/her account is :P" # But for how long was it enabled with weak creds??
    }
    # Fixing stuff
	Set-ADUser -Identity $username -PasswordNeverExpires $false -ChangePasswordAtLogon $true
}

# For now only trying NThash and no LM - could be valuable for stone-age servers to check LM hash exists and is not empty hash value?
function runCheckAgainstServer($server, $distinguishedName, $inputFile, $isWordList = $true) {
    # Grab credentials from a Windows Login popup 
    $creds = Get-Credential

    # PasswordPolicy
    $policy = Get-ADDefaultDomainPasswordPolicy
    write-host -ForeGroundColor Cyan "## Domain default password policy ##`n"
    write-host -ForeGroundColor ('red','green')[$policy.ComplexityEnabled] "Password complexity required:" $policy.ComplexityEnabled
    #write-host -ForeGroundColor ('red','green')[$policy.MinPasswordAge] "Password minage:" $policy.MinPasswordAge
    write-host -ForeGroundColor ('red','green')[$policy.MaxPasswordAge -gt 181] "Password can maximum be # days old:" $policy.MaxPasswordAge.Days
    write-host -ForeGroundColor ('red','green')[$policy.MinPasswordLength -gt 13] "Minimum Password length:" $policy.MinPasswordLength
    write-host -ForeGroundColor ('red','green')[!$policy.ReversibleEncryptionEnabled] "Passwords stored using reversable encryption:" $policy.ReversibleEncryptionEnabled

    write-host -ForeGroundColor Cyan "`nAnything in red should be looked into...`n"
    write-host "Enumerating users of domain...`n"
    Write-Host "Loading data from $inputFile...`n"

    # Resetting:
    # Testing purposes
    #$badPassword = stringToSecureString("Password123")
    #Set-ADUser -Identity "testuser2" -PasswordNeverExpires $true -ChangePasswordAtLogon $false 
    #Set-ADAccountPassword -Identity "testuser2" -Reset -NewPassword $badPassword
    #$knownBad = "D7253A59D621A5E58CD7649C224B9FFD",
	#		     "58A478135A93AC3BF058A5EA0E8FDB71" # Password123

    [string[]]$knownBadLoaded = Get-Content -Path $inputFile

    # Get the AD accounts
    $hashes = Get-ADReplAccount -All -NamingContext $distinguishedName -server $server -Credential $creds
    # Loop through accounts

    # Should we hash everyting first perhaps?? Also, this could be written alot more beautiful
    if($isWordList) {
        foreach($acc in $hashes) {
            $badFlag = $false
            if (![String]::isNullOrEmpty($acc.NTHash)) {
                $hash = [System.BitConverter]::ToString($acc.NTHash).replace("-","")
                #Check if hash is a known bad password
                foreach($p in $knownBadLoaded) {
                    $h = calcNTHash($p)
                    if($h -eq $hash) {
                        #If hash is compared to known bad passwordlist, let's reset password and send them an email, preferably containing the companys password policy
                        $badFlag = $true
                        write-host -ForeGroundColor "red" "`tNOT OK:" $acc.SamAccountName ":::: password is compromised - RESET"
                        resetPassword($acc.SamAccountName)
                        continue
                        #Send email needs to be implemented 
                    }
                }
	       
            }
            if(!$badFlag) { write-host "`t    OK:" $acc.SamAccountName }
        }
        
    } else {
        foreach($acc in $hashes) {
            $badFlag = $false
                if (![String]::isNullOrEmpty($acc.NTHash)) {
                $hash = [System.BitConverter]::ToString($acc.NTHash).replace("-","")
                #Check if hash is a known bad hash 
	            foreach($h in $knownBadLoaded) {
	                if($h -eq $hash) {
		                #If hash is compared to known bad hash array, let's reset password and send them an email, preferably containing the companys password policy
                        $badFlag = $true
		                write-host -ForeGroundColor "red" "`tNOT OK:" $acc.SamAccountName ":::: password is compromised - RESET"
		                resetPassword($acc.SamAccountName)
                        continue
		                #Send email needs to be implemented 
	                }
	            } 
            }
            if(!$badFlag) { write-host "`t    OK:" $acc.SamAccountName }
        }
    }
    Clear-Variable -name 'creds'
}

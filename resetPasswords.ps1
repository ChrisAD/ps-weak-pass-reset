# Requires https://github.com/MichaelGrafnetter/DSInternals to run - Install: Install-Module DSInternals -Force
# https://github.com/MichaelGrafnetter/DSInternals
# Grab credentials from a Windows Login popup 
$creds = Get-Credential

/* Expand this into using https://github.com/berzerk0/Probable-Wordlists/tree/master/Real-Passwords, and also custom list based on keywords from the organisation. 
   As a POC, two known bad hashes are checked. 
   Need to implement an LM NT hashing function to create known bad hashes to compare against */
$knownBad = "D7253A59D621A5E58CD7649C224B9FFD",
			 "58A478135A93AC3BF058A5EA0E8FDB71"

# Get the AD accounts
$hashes = Get-ADReplAccount -All -NamingContext 'DC=133host,DC=local' -server 192.168.56.200 -Credential $creds
# Loop through accounts
foreach($acc in $hashes) {
  write-host "Working:" $acc.SamAccountName
  if (![String]::isNullOrEmpty($acc.NTHash)) {
	  $hash = [System.BitConverter]::ToString($acc.NTHash).replace("-","")
	  #Check if hash is a known bad hash 
	  foreach($h in $knownBad) {
		if($h -eq $hash) {
			#If hash is compared to known bad hash array, let's reset password and send them an email, preferably containing the companys password policy 
			write-host -ForeGroundColor "red" "WEAK PASSWORD. RESET!"
			restPassword($acc.SamAccountName)
			#Send email needs to be implemented 
		}
	  } 
  }
}	



function resetPassword($username) {
	#This probably doesn't work. Needs testing
	#Set-User $username -ChangePasswordAtLogon $true
	$tempPassword = "walkingsoftwareblueelephant"
	Set-ADAccountPassword -Identity $username -Reset -NewPassword $tempPassword
	Set-ADUser -Identity $username -ChangePasswordAtLogon $true 
}

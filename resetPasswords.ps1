$creds = Get-Credential

/* Expand this into using https://github.com/berzerk0/Probable-Wordlists/tree/master/Real-Passwords, and also custom list based on keywords from the organisation. */
$knownBad = "D7253A59D621A5E58CD7649C224B9FFD",
			 "58A478135A93AC3BF058A5EA0E8FDB71"

			 
$hashes = Get-ADReplAccount -All -NamingContext 'DC=133host,DC=local' -server 192.168.56.200 -Credential $creds
foreach($acc in $hashes) {
  write-host "Working:" $acc.SamAccountName
  if (![String]::isNullOrEmpty($acc.NTHash)) {
	  $hash = [System.BitConverter]::ToString($acc.NTHash).replace("-","")
	  foreach($h in $knownBad) {
		if($h -eq $hash) {
			write-host -ForeGroundColor "red" "WEAK PASSWORD. RESET!"
			restPassword($acc.SamAccountName)
			#Send email? 
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

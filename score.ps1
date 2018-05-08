$score=0
$vulns=0
$totalVulns=0
$desktop="C:\Users\Cyber\Desktop\"
$scorebotDirectory = "C:\Users\Cyber\Desktop\"
$scorehtml = "$scorebotDirectory\.score.html"
echo $null > $scorehtml

Function tallyVuln { $global:totalVulns+=1}

function score {
	Param([string]$Description, [int]$Value)
    $global:score+=$Value
    $global:vulns++
    echo "<p>" >> $scorehtml
    echo "$Description : $Value</p>" >> $scorehtml
	#Write-Host "$:global:score"
}

function checkPass {
    [CmdletBinding()]
    Param
    (
        [string]$UserName,
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$Password,
		[switch]$Blank
		
    )
    if (!($UserName) -or ( !($Password) -and !($Blank) ) ) {
        Write-Warning 'Test-LocalCredential: Please specify both user name and password'
    } else {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$ComputerName)
		if (($Blank)) { $Password = $null }
        $DS.ValidateCredentials($UserName, $Password)
    }
}


#seperate items with commas and add quotes around eacho one
#ex: $array = @("test", "test2")
$goodUsers = @() #add authorized users
$badUsers = @() #add unauthorized users
$goodAdmins = @() #add authorized admins
$badAdmins = @() #add unauthorized admins
$requiredServices = @() #add required services by name
$requiredSoftware = @() #not in use
$badServices = @() #add macilicious services
$goodFiles = @() #add required files
$badFiles = @() #add malicious files, binaries, or even directories

foreach ($i in $goodUsers) {
    if (-Not $(net user | Select-String -Pattern "$i")) {
        score "Authorized user $i removed" -2
    }
}

foreach ($i in $badUsers) {
    if (-Not $(net user | Select-String -Pattern "$i")) {
        score "Unauthorized user $i removed" 1
        tallyVuln
    }
}

foreach ($i in $goodAdmins) {
    if (-Not $(net localgroup Administrators | Select-String -Pattern "$i")) {
        score "Authorized administrator $i removed" -2
    }
}

foreach ($i in $badAdmins) {
    if (-Not $(net localgroup Administrators | Select-String -Pattern "$i")) {
        score "Unauthorized administrator $i removed" 1
        tallyVuln
    }
}

foreach ($i in $requiredServices) {
    if (-Not $($(Get-Service -Name "$i").Status | Select-String -Pattern "running")) {
        score "Required service $i not running or disabled" -3
    }
}

foreach ($i in $badServices) {
    if (-Not $($(Get-Service -Name "$i").Status | Select-String -Pattern "running")) {
        score "Unauthorized service $i removed" 3
        tallyVuln
    }
}

foreach ($i in $goodFiles) {
    if (-Not $(Test-Path -Path $i)) {
        score "Authorized file '$i' removed" -3
    }
}

foreach ($i in $badFiles) {
    if (-Not $(Test-Path -Path $i)) {
        score "Unauthorized file/folder '$i' removed" 1
        tallyVuln
    }
}

#other examples

#check if firewall is on
tallyVuln
if ($(netsh advfirewall show allprofiles | Select-String -Pattern 'ON' -CaseSensitive)) {
    score "Firewall enabled" 2

       
}

#process check
tallyVuln
if ($(tasklist /svc /fi 'IMAGENAME eq svchost.exe' | Select-String -Pattern 'windefend')) {
    score "Windows Defender running" 2
}

#registry key check
tallyVuln
if ($($(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin')).ConsentPromptBehaviorAdmin -eq 2 -And $($(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop')).PromptOnSecureDesktop -eq 1) {
    score "UAC set to 'Always Notify'" 2
}

#group policy check
tallyVuln
$string = "$(net accounts | Select-String -Pattern 'Minimum password length')"
if ($( [int]$string.Substring($string.Length-2) -ge 12 )) {
    score "Secure minimum password length set" 1
}
Remove-Variable string

#here, disable_user is our malicious task
tallyVuln
if ($($(schtasks | Select-String -Pattern 'disable_user' | Select-String -Pattern 'Disabled') -Or $(schtasks | Select-String -Pattern 'disable_user'))) {
    score "Malicious task disabled or removed" 3
}

if ($(checkPass -u Cyber -p lonestars)) {
	score "Cyber's password is lonestar" 10000
}

echo "<p><b><font size='7'>Score: $score</p></b></font>" > "$desktop\score.html"
echo "<p><font size='5'>$vulns/$totalVulns</font></p>" >> "$desktop\score.html"
cat $scorehtml >> "$desktop\score.html"
rm $scorehtml

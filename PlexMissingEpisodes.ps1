<#
.CREDITS
	Credit for the credential piece of this script goes to davefunkel here: https://gist.github.com/davefunkel/415a4a09165b8a6027a297085bf812c5
	Credit for the Plex Scanning section of this script goes to MysticRyuujin here: https://github.com/MysticRyuujin/PlexMissingEpisodes/blob/master/PowerShell.ps1

.OBJECTIVES
	Compare you Plex TV Shows to the TVDB database and produce a list of missing episodes and store your Plex credentials securely

.PRE-REQS
	1. PowerShell
	2. TVDB Account
	3. TVDB API Key
	4. Plex Account
	5. Plex Media Server Address

.SCRIPT REGIONS
	GENERAL DETAILS
	GLOBAL CONFIGURATION
	FUCNTIONS
	LOG FILE OUTPUT
	DEBUG LOGGING
	LOG CLEANUP
	CREDENTIAL GENERATION
	PLEX MISSING EPISODE SCAN
	EXAMPLE LOG ENTRIES
	END OF CODE

.INSTRUCTIONS
	1. Make sure you meet all the Pre-Reqs listed above
	2. Modify the Parameters listed below in the CONFIGURATION section for your specific environment
	3. Run the script with the -PrepareCredentials flag, Example: .\script-name.ps1 -PrepareCredentials
		A. Choose AES to store an Encryption Key that can be used across accounts, make sure you protect this key with the appropriate ACLs so others cannot access it
		D. Choose DPAPI if you want only the account you are logged into to be able to run the script, more secure and recommended
	5. Provide your Plex Username and Password and they will be stored securely 
	6. Now you can run this script again with the -Execution flag, Example: \script-name.ps1 -Execution
	7. If you configured the Parameters correctly you will get a text file with all your missing episodes
	8. You can now run this script on a schedule and/or automate a process around this it
	
.CONFIGURATION
	This is the list of parameters you will want to change for your specific environment
	I'd recommend searching for these in the script and modifying them as needed
		$scriptName
			This will be used in file paths below, avoid using spaces and special characters if not necessary
			The default is $scriptName = "PlexMissingEpisodes"
		$rootFolder
			The root folder that this script uses
			The default is $rootFolder = "C:\scripts\$scriptName"
		$credentialFileDir
			This is the location where the credential file containing your Plex Username and Password is stored
			The recommend using the default, which is $credentialFileDir = $rootFolder
		$PlexServer
			This is your Plex Server Address, either IP or FQDN with PORT number, if using a reverse proxy then port number isn't needed
			The unconfigured value is $PlexServer = "https://IPADDRESS:PORT"			
		$FileOutputPath
			The path to where you want the scan results placed and the name of the file and extension you want used
			The default is $FileOutputPath = "$rootFolder\MissingEpisodes.txt"
		$TVDBAPIKey
			Your TVDB API Key
			The unconfigured value is $TVDBAPIKey = "YOUR_TVDBAPIKey"
			You can request one of these easily from the API Keys section on your TVDB Account under Dashboard--->Account--->API Keys
			When asked to provide a reason tell them what you'll be using it for
			API Key approval can take a few days so be patient
			Keep in mind that legacy API keys will be deprecated in 2021 and you will need a v4 API key after that
		$TVDBUserKey
			Your Unique TVDB User Key
			The unconfigured value is $TVDBUserKey = "YOUR_TVDBUserKey"
			You can find this under Dashboard--->Account--->Edit Information on your TVDB Account
		$TVDBUserName
			Your TVDB Username
			The unconfigured value is $TVDBUserName = "YOUR_TVDBUserName"
		$IgnoreList
			The list of shows you want ignored during the scan for missing episodes
			This is useful if you know there are seasons or episodes that you don't have and/or don't want for a certain series
			The Example Ignore List can be found below by searching the script for $IgnoreList
			
.UPDATES
	8/30/2020
		Added Output to txt file into script
		Added instructions and explanations for various parts of the script
		Added the use of an encrypted credential for storing your Plex password
		Added dedicated parameters for $TheTVDBAuthentication
#>

<##====================================================================================
	GENERAL DETAILS
##===================================================================================#>

<#
.SYNOPSIS
	This version of the template has inbuilt functions to capture credentials and store it securely for reuse
	Avoids the need to have plaintext passwords in the script

.DESCRIPTION
	There are two main components of this script:
	1. Prepare Credentials
		This phase is run at least once.  It generates a secure hashed credential file that can be used by the script.
		Re-running this phase will overwrite the existing credential file.
		There are two modes provided:
			- DPAPI:  Recommended.  More secure. Requires both 'PrepareCredentials' and 'Execution' phases to be run by the same user account on the same machine to be able to decrypt key
			- AES:  Only to be used when service account cannot be used to run in interactive mode (and thus can't run PrepareCredentials). The AES.Key file that is generated is decryptable by anyone, so you must protect read access to this file using ACLs.
				
	2. Execution
		This phase is used to actually perform the execution of this script.  'Prepare Credentials' must have been run at least once.
	
	Author: David Lee (david.lee@kloud.com.au)
	Change Log:
		07/12/15	0.1	DL	Initial Release

.PARAMETER 
	PrepareCredentials
		Run with this switch at least once.  Two methods are provided for generating the secure hashed credential file based on your requirements.

.PARAMETER 
	Execution
		Run this switch when you want to run this script normally

.PARAMETER 
	param1
		These parameters are automatched against the parameters defined in this script

.PARAMETER 
	param2
		Use a .parameter for each one of your parameters

.EXAMPLE
	.\script-name.ps1 -PrepareCredentials

.EXAMPLE
	.\script-name.ps1 -Execution -param1 value1 -param2 value2
	
#>
[CmdletBinding()]
Param([switch]$PrepareCredentials, [switch]$Execution, $param1, $param2)

<##====================================================================================
	GLOBAL CONFIGURATION
##===================================================================================#>
$erroractionpreference = "stop"

$debugFlag = $PSBoundParameters.Debug.IsPresent
$verboseFlag = $PSBoundParameters.Verbose.IsPresent

# Use this to control whether to break on debugs or not
if($debugFlag -eq $true)
{
	# If you want a break prompt on each Write-Debug entry, use "inquire"
	# Otherwise use "continue" to simply output debug log (recommended)
	$debugPreference = "continue"
}

# This will be used in file paths below, so avoid using spaces and special characters
$scriptName = "PlexMissingEpisodes"  

# Root Folder
$rootFolder = "C:\scripts\$scriptName"

# Secure Credential File
$credentialFileDir = $rootFolder
$credentialFilePath = "$credentialFileDir\$scriptName-SecureStore.txt"

# Path to store AES File (if using AES mode for PrepareCredentials)
$AESKeyFileDir = $rootFolder
$AESKeyFilePath = "$AESKeyFileDir\$scriptName-AES.key"

# Output Log File Name:  DescriptiveName_yyyy-MM-ddTHHmm.log
$outputLogFileName = "$scriptName_" + (get-date -f yyyy-MM-ddTHHmm) + ".log"

# Change Log File Directory as necessary
$outputLogDir = "$rootFolder\Logs"
# Full Path of Log File
$outputLogPath = "$outputLogDir\$outputLogFileName"

# Log Age Limit (in days).  Log files older than this will be auto deleted
$logAgeLimit = 30

# This is where I put global variables and the like for easy access an updates

<##====================================================================================
	FUNCTIONS
##===================================================================================#>

<#
.SYNOPSIS
	Initializes the output log file. 

.DESCRIPTION
	Execute this function at the beginning of your main code to ensure the log file path
	exists, and if it doesn't, create the folder paths to ensure future Write-Log calls
	will run without issue
	
	This function can also be modified to create log file headers
	
.PARAMETER 
	overwrite
		Set this flag to overwrite any existing log files.  Otherwise default is to append
		to the existing log file
	
.PARAMETER 
	headerText
		Optional ability to define some text at the start of eveyr initialization of the log file
		Useful if you are not overwriting the log file each time script is run
#>
function Start-LogFile([switch]$overwrite, $headerText)
{
	# Check if log dir exists, if not, create it
	if(!(Test-Path $outputLogDir))
	{
		New-Item -type Directory $outputLogDir | out-null
	}
	Write-Output $headerText
	
	try
	{
		if($overwrite -eq $true)
		{
			set-content $outputLogPath $headerText
		}
		else
		{
			add-content $outputLogPath $headerText
		}
	}
	catch
	{
		Write-Warning "Could not initialize the log file: $outputLogPath"
	}
}

<##====================================================================================
	LOG FILE OUTPUT
##===================================================================================#>

<#
.SYNOPSIS
	Writes to an entry into the output log file, and to the console if -Verbose is used

.DESCRIPTION
	This is a useful function for log file outputs.  Change the structure of this output
	as necessary for your scripts.
	If the -Verbose flag is set, then the log file message will also be written to the console
	using the Write-Verbose command
	
.PARAMETER type
	Optional, but can use to tag the log entry type. Recommend to use one of INFO,WARNING,ERROR
	Will default to INFO if non specified.
	NOTE:  If you wish to write a DEBUG log entry, use the Write-DebugLog function

.PARAMETER message
	The text to write to your output file
#>
function Write-Log($message, $type)
{
	if($type -eq $null -or $type -eq "")
	{
		$type = "INFO"
	}
	
	try
	{
		# Log Entry Structure:  [Date] [TYPE] [MESSAGE]
		$logEntry = (Get-Date -format u) + "`t" + $type.ToUpper() + "`t" + $message
		if($type -eq "WARNING")
		{
			Write-Host -foregroundcolor Yellow $logEntry
		}
		elseif($type -eq "ERROR")
		{
			Write-Host -foregroundcolor Red $logEntry
		}
		else
		{
			Write-Host $logEntry
		}					
		Add-Content $outputLogPath $logEntry
	}
	catch
	{
		Write-Warning "Could not write entry to output log file: $outputLogPath `nLog Entry:$message"
	}
}

<##====================================================================================
	DEBUG LOGGING
##===================================================================================#>

<#
.SYNOPSIS
	Writes to an entry in the output log file only if the -debug parameter was set in the script

.DESCRIPTION
	This is a useful function for performing debug logging.  It will use both the in built Write-Debug
	function as well as creating an entry to the log file with a DEBUG type 

.PARAMETER message
	The debug text to write to your output file
#>
function Write-DebugLog($message)
{
	Write-Debug $message
	try
	{
		# Only write to the log file if the -Debug parameter has been set
		if($script:debugFlag -eq $true)
		{
			# Log Entry Structure: [Date] [TYPE] [MESSAGE]
			$logEntry = (Get-Date -format u) + "`t" + "DEBUG" + "`t" + $message
			Add-Content $outputLogPath $logEntry
		}
	}
	catch
	{
		Write-Warning "Could not write entry to output log file: $outputLogPath `nLog Entry:$message"
	}
}

<##====================================================================================
	LOG CLEANUP
##===================================================================================#>

<#
.SYNOPSIS
	Cleans up log files

.DESCRIPTION
	This is a useful function when scripts are run regularly and thus create lots of log files.
	Based on a log age date, it will remove all log files older than that period
	Uses a Global variable for the log age date

	.PARAMETER logPath
	Folder location for log files to remove

	.PARAMETER fileExtension
	Type of files to delete.  Use a wildcard format like "*.log"
#>
function Cleanup-LogFiles($logPath, $fileExtension)
{
	# Determine the date of which files older than specific period will be deleted
	$dateToDelete = (Get-Date).AddDays(-$logAgeLimit)
	$filesToDelete = Get-ChildItem $logPath -Include $fileExtension -Recurse | where{$_.LastWriteTime -le $dateToDelete}
	foreach($file in $filesToDelete)
	{
		$filePath = $file.FullName
		try
		{
			Write-DebugLog "Deleting $file..."
			Remove-Item $filePath -force | out-null
		}
		catch
		{
			Write-Log "Failed to delete old log file ($filePath)" -type WARNING 
		}
	}
}

<##====================================================================================
	CREDENTIAL GENERATION
##===================================================================================#>

# Checks to make sure at least either PrepareCredentials or Execution switches are run and not both.
if(($PrepareCredentials -eq $false -and $Execution -eq $false) -or ($PrepareCredentials -eq $true -and $Execution -eq $true))
{
	Write-Host -foreground red "[ERROR] You must specify either -PrepareCredentials or -Execution"
	exit -1
}

# Leave this code as is.  This is the code to generate the secure files.
if($PrepareCredentials -eq $true)
{
	try
	{
		
		$headerText = (Get-Date -format u) + "`t" + "INIT" + "`t" + "****$scriptName log initialised in PrepareCredentials mode.****"
		Start-LogFile -headerText $headerText  # Initialize the log file with a header	

		# Provide two 
		$title = "Prepare Credentials Encryption Method"
		$message = "Which mode do you wish to use?"

		$DPAPI = New-Object System.Management.Automation.Host.ChoiceDescription "&DPAPI", `
			"Use Windows Data Protection API.  This uses your current user context and machine to create the encryption key."

		$AES = New-Object System.Management.Automation.Host.ChoiceDescription "&AES", `
			"Use a randomly generated SecureKey for AES.  This will generate an AES.key file that you need to protect as it contains the encryption key."

		$options = [System.Management.Automation.Host.ChoiceDescription[]]($DPAPI, $AES)

		$choice = $host.ui.PromptForChoice($title, $message, $options, 0) 

		switch ($choice)
		{
			0 {$encryptMode = "DPAPI"}
			1 {$encryptMode = "AES"}
		}
		Write-DebugLog "Encryption mode $encryptMode was selected to prepare the credentials."
			
		Write-Log "Collecting Credentials to create a secure credential file..." -Type INFO
		# Collect the credentials to be used.
		$creds = Get-Credential
		
		# Store the details in a hashed format
		$userName = $creds.UserName
		$passwordSecureString = $creds.Password

		if($encryptMode -eq "DPAPI")
		{
			$password = $passwordSecureString | ConvertFrom-SecureString
		}
		elseif($encryptMode -eq "AES")
		{
			# Generate a random AES Encryption Key.
			$AESKey = New-Object Byte[] 32
			[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
			
			# Store the AESKey into a file. This file should be protected!  (e.g. ACL on the file to allow only select people to read)

			# Check if Credential File dir exists, if not, create it
			if(!(Test-Path $AESKeyFileDir))
			{
				New-Item -type Directory $AESKeyFileDir | out-null
			}
			Set-Content $AESKeyFilePath $AESKey   # Any existing AES Key file will be overwritten		
			$password = $passwordSecureString | ConvertFrom-SecureString -Key $AESKey
		}
		else
		{
			# Placeholder in case there are other EncryptModes
		}
		
		
		# Check if Credential File dir exists, if not, create it
		if(!(Test-Path $credentialFileDir))
		{
			New-Item -type Directory $credentialFileDir | out-null
		}
		
		# Contents in this file can only be read and decrypted if you have the encryption key
		# If using DPAPI mode, then this can only be ready by the user that ran this script on the same machine
		# If using AES mode, then the AES.key file contains the encryption key
		
		Set-Content $credentialFilePath $userName   # Any existing credential file will be overwritten
		Add-Content $credentialFilePath $password

		if($encryptMode -eq "AES")
		{
			Write-Host -foreground Yellow "IMPORTANT! Make sure you restrict read access, via ACLs, to the AES.Key file that has been generated to ensure stored credentials are secure."
		}

		Write-Log "Credentials collected and stored." -Type INFO
		Write-Host -foreground Green "Credentials collected and stored."
	}
	catch
	{
		$errText = $error[0]
		Write-Log "Failed to Prepare Credentials.  Error Message was: $errText" -type ERROR
		Write-Host -foreground red "Failed to Prepare Credentials.  Please check Log File."
		Exit -1
	}
}


if($Execution -eq $true)
{

	$headerText = (Get-Date -format u) + "`t" + "INIT" + "`t" + "****$scriptName log initialised in Execution mode****"
	Start-LogFile -headerText $headerText  # Initialize the log file with a header	

	# Check to ensure we have a secure credential file (i.e. -PrepareCredentials has been run) and that the contents are valid
	if(!(Test-Path $credentialFilePath))
	{
		Write-Log "Could not find a secure credential file at $credentialFilePath.  Exiting." -Type ERROR
		Write-Host -foreground red "[ERROR] Could not find a secure credential file at $credentialFilePath.  Ensure that you have run the -PrepareCredentials parameter at least once for this script."
		exit -1	
	}
	
	# Check to see if we have an AES Key file.  If so, then we will use it to decrypt the secure credential file
	if(Test-Path $AESKeyFilePath)
	{
		try
		{
			Write-DebugLog "Found an AES Key File.  Using this to decrypt the secure credential file."
			$decryptMode = "AES"
			$AESKey = Get-Content $AESKeyFilePath
		}
		catch
		{
			$errText = $error[0]
			Write-Log "AES Key file detected, but could not be read.  Error Message was: $errText" -type ERROR
			exit -1
		}
	}
	else
	{
		Write-DebugLog "No AES Key File found.  Using DPAPI method, which requires same user and machine to decrypt the secure credential file."
		$decryptMode = "DPAPI"
	}

	try
	{	
		Write-DebugLog "Reading secure credential file at $credentialFilePath."
		$credFiles = Get-Content $credentialFilePath
		$userName = $credFiles[0]
		if($decryptMode -eq "DPAPI")
		{
			$password = $credFiles[1] | ConvertTo-SecureString 
		}
		elseif($decryptMode -eq "AES")
		{
			$password = $credFiles[1] | ConvertTo-SecureString -Key $AESKey
		}
		else
		{
			# Placeholder in case there are other decrypt modes
		}

		Write-DebugLog "Creating credential object..."
		$credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $userName, $password
		$passwordClearText = $credObject.GetNetworkCredential().Password
		Write-DebugLog "Credential store read.  UserName is $userName and Password is $passwordClearText"


<##====================================================================================
	PLEX MISSING EPISODE SCAN
##===================================================================================#>

<#
.PARAMETERS
	$PlexServer
		This is your Plex Server Address, either IP or FQDN with PORT number, if using a reverse proxy then port number isn't needed
		The unconfigured value is $PlexServer = "https://IPADDRESS:PORT"			
	$FileOutputPath
		The path to where you want the scan results placed and the name of the file and extension you want used
		The default is $FileOutputPath = "$rootFolder\MissingEpisodes.txt"
	$TVDBAPIKey
		Your TVDB API Key
		The unconfigured value is $TVDBAPIKey = "YOUR_TVDBAPIKey"
		You can request one of these easily from the API Keys section on your TVDB Account under Dashboard--->Account--->API Keys
		When asked to provide a reason tell them what you'll be using it for
		API Key approval can take a few days so be patient
		Keep in mind that legacy API keys will be deprecated in 2021 and you will need a v4 API key after that
	$TVDBUserKey
		Your Unique TVDB User Key
		The unconfigured value is $TVDBUserKey = "YOUR_TVDBUserKey"
		You can find this under Dashboard--->Account--->Edit Information on your TVDB Account
	$TVDBUserName
		Your TVDB Username
		The unconfigured value is $TVDBUserName = "YOUR_TVDBUserName"
	$IgnoreList
		The list of shows you want ignored during the scan for missing episodes
		This is useful if you know there are seasons or episodes that you don't have and/or don't want for a certain series
		The Example Ignore List can be found below by searching the script for $IgnoreList
#>

# Location where the file with missing episodes will be created
$FileOutputPath = "$rootFolder\MissingEpisodes.txt"

# Your TVDB API Key
$TVDBAPIKey = "YOUR_TVDBAPIKey"
# Your Unique TVDB User Key
$TVDBUserKey = "YOUR_TVDBUserKey"
# Your TVDB Username
$TVDBUserName = "YOUR_TVDBUserName"

# TheTVDB Authentication Information
$TheTVDBAuthentication = @{
    "apikey"   = $TVDBAPIKey
    "userkey"  = $TVDBUserKey
    "username" = $TVDBUserName
}

# Plex Server Information
$PlexServer = "https://IPADDRESS:PORT"

# Array of show names to ignore, examples included
$IgnoreList = @(
    "Chopped"
    "Daniel Tiger's Neighborhood"
    "Penn & Teller: Fool Us"
    "Supergirl"
    "The Flash (2014)"
    "The Magicians (2015)"
    "The Voice"
    "The Walking Dead"
    "Top Gear"
    "Whose Line Is It Anyway? (US)"
)

# Ignore Plex Certificate Issues
if ($PlexServer -match "https") {
    Add-Type "using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; } }"
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}
		
# Try to authenticate with TheTVDB API to get a token
try {
    $TheTVDBToken = (Invoke-RestMethod -Uri "https://api.thetvdb.com/login" -Method Post -Body ($TheTVDBAuthentication | ConvertTo-Json) -ContentType 'application/json').token
}
catch {
    Write-Host -ForegroundColor Red "Failed to get TheTVDB API Token:"
    Write-Host -ForegroundColor Red $_
    break
}

# Create TheTVDB API Headers
$TVDBHeaders = [System.Collections.Generic.Dictionary[[String],[String]]]::new()
$TVDBHeaders.Add("Accept", "application/json")
$TVDBHeaders.Add("Authorization", "Bearer $TheTVDBToken")

# Create Plex Headers
$PlexHeaders = [System.Collections.Generic.Dictionary[[String],[String]]]::new()
$PlexHeaders.Add("Authorization", "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$PlexUsername`:$PlexPassword")))")
$PlexHeaders.Add("X-Plex-Client-Identifier", "MissingTVEpisodes")
$PlexHeaders.Add("X-Plex-Product", "PowerShell")
$PlexHeaders.Add("X-Plex-Version", "V1")

# Try to get Plex Token
try {
    $PlexToken = (Invoke-RestMethod -Uri 'https://plex.tv/users/sign_in.json' -Method Post -Credential $credObject -Headers $PlexHeaders).user.authToken
    $PlexHeaders.Add("X-Plex-Token", $PlexToken)
    [void]$PlexHeaders.Remove("Authorization")
}
catch {
    Write-Host -ForegroundColor Red "Failed to get Plex Auth Token:"
    Write-Host -ForegroundColor Red $_
    break
}

# Try to get the Library IDs for TV Shows
try {
    $TVKeys = ((Invoke-RestMethod -Uri "$PlexServer/library/sections" -Headers $PlexHeaders).MediaContainer.Directory | Where-Object type -eq "show").key
}
catch {
    Write-Host -ForegroundColor Red "Failed to get Plex Library Sections:"
    if ($_.Exception.Response.StatusDescription -eq "Unauthorized") {
        Write-Host -ForegroundColor Red "Ensure that your source IP is configured under the 'List of IP addresses and networks that are allowed without auth' setting"
    }
    else {
        Write-Host -ForegroundColor Red $_
    }
    break
}

# Get all RatingKeys
$RatingKeys = [System.Collections.Generic.List[int]]::new()
ForEach ($TVKey in $TVKeys) {
    $SeriesInfo = (Invoke-RestMethod -Uri "$PlexServer/library/sections/$TVKey/all/" -Headers $PlexHeaders).MediaContainer.Directory
    ForEach ($Series in $SeriesInfo) {
        if (-not $IgnoreList.Contains($Series.title)) {
            [void]$RatingKeys.Add($Series.ratingKey)
        }
    }
}
$RatingKeys = $RatingKeys | Sort-Object -Unique

# Get all Show Data
$PlexShows = @{ }
$Progress = 0
ForEach ($RatingKey in $RatingKeys) {
    $ShowData = (Invoke-RestMethod -Uri "$PlexServer/library/metadata/$RatingKey/" -Headers $PlexHeaders).MediaContainer.Directory
    $Progress++
    Write-Progress -Activity "Collecting Show Data" -Status $ShowData.title -PercentComplete ($Progress / $RatingKeys.Count * 100)
    $GUID = $ShowData.guid -replace ".*//(\d+).*", '$1'
    if ($PlexShows.ContainsKey($GUID)) {
        [void]$PlexShows[$GUID]["ratingKeys"].Add($RatingKey)
    }
    else {
        [void]$PlexShows.Add($GUID, @{
                "title"      = $ShowData.title
                "ratingKeys" = [System.Collections.Generic.List[int]]::new()
                "seasons"    = @{ }
            }
        )
        [void]$PlexShows[$GUID]["ratingKeys"].Add($ShowData.ratingKey)
    }
}

# Get Season data from Show Data
$Progress = 0
ForEach ($GUID in $PlexShows.Keys) {
    $Progress++
    Write-Progress -Activity "Collecting Season Data" -Status $PlexShows[$GUID]["title"] -PercentComplete ($Progress / $PlexShows.Count * 100)
    ForEach ($RatingKey in $PlexShows[$GUID]["ratingKeys"]) {
        $Episodes = (Invoke-RestMethod -Uri "$PlexServer/library/metadata/$RatingKey/allLeaves" -Headers $PlexHeaders).MediaContainer.Video
        $Seasons = $Episodes.parentIndex | Sort-Object -Unique
        ForEach ($Season in $Seasons) {
            if (!($PlexShows[$GUID]["seasons"] -contains $Season)) {
                $PlexShows[$GUID]["seasons"][$Season] = [System.Collections.Generic.List[hashtable]]::new()
            }
        }
        ForEach ($Episode in $Episodes) {
            if ((!$Episode.parentIndex) -or (!$Episode.index)) {
                Write-Host -ForegroundColor Red "Missing parentIndex or index"
                Write-Host $PlexShows[$GUID]
                Write-Host $Episode
            }
            else {
                [void]$PlexShows[$GUID]["seasons"][$Episode.parentIndex].Add(@{$Episode.index = $Episode.title })
            }
        }
    }
}

# Missing Episodes
$Missing = @{ }
$Progress = 0
ForEach ($GUID in $PlexShows.Keys) {
    $Progress++
    Write-Progress -Activity "Collecting Episode Data from TheTVDB" -Status $PlexShows[$GUID]["title"] -PercentComplete ($Progress / $PlexShows.Count * 100)
    $Page = 1
    try {
        $Results = (Invoke-RestMethod -Uri "https://api.thetvdb.com/series/$GUID/episodes?page=$page" -Headers $TVDBHeaders)
        $Episodes = $Results.data
        while ($Page -lt $Results.links.last) {
            $Page++
            $Results = (Invoke-RestMethod -Uri "https://api.thetvdb.com/series/$GUID/episodes?page=$page" -Headers $TVDBHeaders)
            $Episodes += $Results.data
        }
    }
    catch {
        Write-Warning "Failed to get Episodes for $($PlexShows[$GUID]["title"])"
        $Episodes = $null
    }
    ForEach ($Episode in $Episodes) {
        if (!$Episode.airedSeason) { continue } # Ignore episodes with blank airedSeasons (#11)
        if ($Episode.airedSeason -eq 0) { continue } # Ignore Season 0 / Specials
        if (!$Episode.firstAired) { continue } # Ignore unaired episodes
        if ((Get-Date).AddDays(-1) -lt (Get-Date $Episode.firstAired)) { continue } # Ignore episodes that aired in the last ~24 hours
        if (!($PlexShows[$GUID]["seasons"][$Episode.airedSeason.ToString()].Values -contains $Episode.episodeName)) {
            if (!($PlexShows[$GUID]["seasons"][$Episode.airedSeason.ToString()].Keys -contains $Episode.airedEpisodeNumber)) {
                if (!$Missing.ContainsKey($PlexShows[$GUID]["title"])) {
                    $Missing[$PlexShows[$GUID]["title"]] = [System.Collections.Generic.List[hashtable]]::new()
                }
                [void]$Missing[$PlexShows[$GUID]["title"]].Add(@{
                        "airedSeason"        = $Episode.airedSeason.ToString()
                        "airedEpisodeNumber" = $Episode.airedEpisodeNumber.ToString()
                        "episodeName"        = $Episode.episodeName
                    })
            }
        }
    }
}

$output = 
	ForEach ($Show in ($Missing.Keys | Sort-Object)) {
		ForEach ($Season in ($Missing[$Show].airedSeason | Sort-Object -Unique)) {
			$Episodes = $Missing[$Show] | Where-Object airedSeason -eq $Season
			ForEach ($Episode in $Episodes) {
				"{0} S{1:00}E{2:00} - {3}" -f $Show, [int]$Season, [int]$Episode.airedEpisodeNumber, $Episode.episodeName
			}
		}
	}
$output | Out-File $FileOutputPath

<##====================================================================================
	EXAMPLE LOG ENTRIES
##=====================================================================================	
		# Example Log File Entry
		Write-Log "No Type Flag creates an INFO entry"
		Write-Log "Or you can create a WARNING entry" -type "WARNING"
		Write-Log "Or an ERROR entry" -type "ERROR"

		# Example Debug Log
		Write-DebugLog "This writes stuff if the -Debug flag is set in the script"
##===================================================================================#>
		
	}
	catch
	{
		$errText = $error[0]
		Write-Log "Could not execute in Execution mode.  Error Message was: $errText" -type ERROR
		exit -1
	}

}

<##====================================================================================
	END OF CODE
##===================================================================================#>
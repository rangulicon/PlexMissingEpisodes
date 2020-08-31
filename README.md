## CREDITS

Credit for the credential piece of this script goes to davefunkel here: https://gist.github.com/davefunkel/415a4a09165b8a6027a297085bf812c5

Credit for the Plex Scanning section of this script goes to MysticRyuujin here: https://github.com/MysticRyuujin/PlexMissingEpisodes/blob/master/PowerShell.ps1

## OBJECTIVES

Compare you Plex TV Shows to the TVDB database and produce a list of missing episodes and store your Plex cedentials securely

## PRE-REQS

1. PowerShell
2. TVDB Account
3. TVDB API Key
4. Plex Account
5. Plex Media Server Address

## SCRIPT REGIONS

01. GENERAL DETAILS
02. GLOBAL CONFIGURATION
03. FUCNTIONS
04. LOG FILE OUTPUT
05. DEBUG LOGGING
06. LOG CLEANUP
07. CREDENTIAL GENERATION
08. PLEX MISSING EPISODE SCAN
09. EXAMPLE LOG ENTRIES
10. END OF CODE

## INSTRUCTIONS

1. Make sure you meet all the Pre-Reqs listed above
2. Modify the parameters listed below in the CONFIGURATION section for your specific environment
3. Run the script with the -PrepareCredentials flag, Example: .\script-name.ps1 -PrepareCredentials
	- Choose AES to store an Encryption Key that can be used across acounts, make sure you protect this key with the appropriate ACLs so others cannot access it
	- Choose DPAPI if you want only the account you are logged into to be able to run the script, more secure and recommended
5. Provide your Plex Username and Password and they will be stored securely 
6. Now you can run this script again with the -Execution flag, Example: \script-name.ps1 -Execution
7. If you configured the parameters correctly you will get a text file with all your missing expisodes
8. You can now run this script on a schedule and/or automate a process around this it
	
## CONFIGURATION

This is the list of parameters you will want to change for your specific environment

I'd recommend searching for these in the script and modifying them as needed
	
**$scriptName**

- This will be used in file paths below, avoid using spaces and special characters if not necessary

- The default is $scriptName = "PlexMissingEpisodes"

**$rootFolder**
	
- The root folder that this script uses

- The default is $rootFolder = "C:\scripts\$scriptName"

**$credentialFileDir**

- This is the location where the credential file containing your Plex Username and Password is stored

- The recommend using the default, which is $credentialFileDir = $rootFolder

**$PlexServer**

- This is your Plex Server Address, either IP or FQDN with PORT number, if using a reverse proxt then port number isn't needed
	
- The unconfigured value is $PlexServer = `"https://IPADDRESS:PORT"`			

**$FileOutputPath**

- The path to where you want the scan results placed and the name of the file and extension you want used

- The default is $FileOutputPath = "$rootFolder\MissingEpisodes.txt"

**$TVDBAPIKey**

- Your TVDB API Key

- The unconfigured value is $TVDBAPIKey = "YOUR_TVDBAPIKey"

- You can request one of these easily from the API Keys section on your TVDB Account under Dashboard--->Account--->API Keys

- When asked to provide a reason tell them what you'll be using it for

- API Key approval can take a few days so be patient

- Keep in mind that legacy API keys will be deprecated in 2021 and you will need a v4 API key after that

**$TVDBUserKey**

- Your Unique TVDB User Key

- The unconfigured value is $TVDBUserKey = "YOUR_TVDBUserKey"

- You can find this under Dashboard--->Account--->Edit Information on your TVDB Account

** $TVDBUserName **

- Your TVDB Username

- The unconfigured value is $TVDBUserName = "YOUR_TVDBUserName"
		
**$IgnoreList**

- The list of shows you want ignored during the scan for missing episodes

- This is useful if you know there are seasons or episodes that you don't have and/or don't want for a certain series

- The Example Ignore List can be found below by searching the script for $IgnoreList
			
# UPDATES

8/30/2020
	
- Added Output to txt file into script

- Added instructions and explanations for various parts of the script

- Added the use of an encrypted credential for storing your Plex password

- Added dedicated parameters for $TheTVDBAuthentication

- Removed Perl Script

- Updated ReadMe

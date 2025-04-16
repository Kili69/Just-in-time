# Introduction 
This is a active directory Just-In-Time solution based on the Active Directory Version 2016 or higher and powershell scripts. The reduce the risk of a administrator ist 24x7 administrator on all or many computers. 
The principal of this project is: Each server has a domain local group in the active directory. This group is added to the local administrators of a server via group policy.  
A user can request local administrator privilege due writeing a event to the Tier 1 Local Administrator event log. A schedule task ist tirggered on this event. This schedule task is running as a Group Managed Service Account and add the user will be added time restricted to this group. Now the user is time restricted local administrator on a singel server.  

The project is based on:
1) Active directory Forest functional Level Windwos Server 2016
2) A schedule task who create a group for each computer object. 
3) A Group Policy who add the computer specified group to the local administrators group on each computer
4) A scheduled task to add a user to one of these tasks. this task is triggered by an event
5) A powershell script which triggers the scheduled task

# Getting Started
Before you start with this solutions, take care the Active Directory Forest functional levle is Windows Server 2016 or higher.
Provide a AD joined server with privileged access to T0 users or local user accounts. Take care Tier 1 users have only user privileg.

Pre-Reqs:
- AD Optional feature "Privileged Access Management Feature" needs to be installed
  
	  Enable-ADOptionalFeature "Privileged Access Management Feature" –Scope ForestOrConfigurationSet -Target <domainFQDN>
- RSAT-AD-Powershell feature needs to be installed on T1 JiT mgmt server


1.	Installation process
1.1. Tier 1 local user management server
Provide a Windows Server 2012 or higher for the Tier 1 local administrator management
1.2. copy scripts
copy the powershell scripts of this solution to  a directory with read privleged for any authenticated users
1.2. Organizational Unit
Create a Organizational unit for Tier 1 Local Administrators groups. Take care Tier 1 / Tier 2 users have no write access to this OU
1.3 run configuration
run the configuration config-jit.ps1. the configuration script asks for:
- Admin Prefix: is the prefix for the active directory group for the local administrator
- Domain: the DNS Name of the active Directory domain
- OU: the distinguished path of the O where the groups for the local administrators are created
- Tier0 Server group name: Is the name of the group, who conatins all Tier 0 servers objects
- Default elevation time: This is default value for elevated time if no time is specified in the request
- Installation directory: The working directory for the powershell scripts
- Elevation time for new server object: GroupManagementTaskRerun is the time how often a schedule task searches for new Tier 1 servers and removes permanent members
- Name of the group managed service acocunt: This account maintains the groups in the organizational units
3.	Create a group policy for local administrators
Create a group policy with a group policy preferences who adds the <Admin-Prefix>%COMPUTERNAME% to the local administrators. Assing this group policy to the Tier 1 server OU
- take care on localization OS languages (e.g.: on french systems, local administrators group is named "Administrateurs")
- you might need to use WMI filter for different server OS', e.g.:
  
			german:
  			select * FROM Win32_OperatingSystem WHERE OSLanguage=1031
			english:
			select * FROM Win32_OperatingSystem WHERE OSLanguage=1033
			french:
			select * FROM Win32_OperatingSystem WHERE OSLanguage=1036
			
    [MS-OE376]: Part 4 Section 7.6.2.39, LCID (Locale ID) | Microsoft Learn
    https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oe376/6c085406-a698-4e12-9d4d-c3b0ee3dbc4a

# Build and Test
1. Validate the schedule task who creates the groups in the active directory
2. Validate the Group Policy add the groups create in the step above to the local administrator groups
3. Create a local administrator request due running the requestadminaccess.ps1
4. Validate the request is written to the Tier 1 Management event log
5. validate the requested user is member of the active directory group
6. logon as the requested user to the server and validate the user is local administrator and logoff
7. wait till the elevation time is expired
8. logon as the requested user and validate the user has no more administrator privileges

# Contribute
TODO: Explain how other users and developers can contribute to make your code better. 


<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides the functionality to add a user account to the list of users that have "SendOnBehalf" rights for a specific mailbox. The following steps are provided

 1. Enter a name to lookup the user account that should aquire the "SendOnBehalf" rights.
 2. The result will show you a list of matching users. You will need select to correct one
 3. Enter a name to lookup the mailbox
 4. The result will show you a list of mailboxes. You will need select to correct one
 5. On submit, the user will be added to the list of users that has the "SendOnBehalf" right.

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/16  |
| 1.0.0   | Initial release | 2021/04/29  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Post-setup configuration](#post-setup-configuration)
* [Manual resources](#manual-resources)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.


## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>ExchangeConnectionUri</td><td>********</td><td>Exchange server URI</td></tr>
  <tr><td>ExchangeAdminUsername</td><td>domain/user</td><td>Exchange server admin account</td></tr>
  <tr><td>ExchangeAdminPassword</td><td>********</td><td>Exchange server admin password</td></tr>
  <tr><td>ExchangeAuthentication</td><td>kerberos</td><td>Exchange server authentication method</td></tr>
  <tr><td>ExchangeSendOnBehalfUserSearchOU</td><td>Example.com/Users</td><td>OrganizationalUnit to search for useraccount</td></tr>
   <tr><td>ExchangeSendOnBehalfMailboxSearchOU</td><td>Example.com/Users</td><td>OrganizationalUnit to search for mailbox</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source '[powershell-datasource]_Exchange-On-Premises-SendOnbBehalf-Get-Users'
This Powershell data source runs a query to search for the user.

### Powershell data source '[powershell-datasource]_Exchange-On-Premises_SendOnBehalf-List-Mailboxes'
This Powershell data source runs a query to search for the mailbox.

### Delegated form task '[task]_Exchange-On-Premises-SendOnBehalf'
This delegated form task adds the user to the "SendOnBehalf" rights list of the mailbox

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/252-helloid-sa-exchange-onpremises-sendonbehalf)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
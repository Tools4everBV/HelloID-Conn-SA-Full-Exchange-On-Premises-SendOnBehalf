# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("Users") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("Exchange Administration") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> ExchangeConnectionUri
$tmpName = @'
ExchangeConnectionUri
'@ 
$tmpValue = ""
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> ExchangeAdminPassword
$tmpName = @'
ExchangeAdminPassword
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> ExchangeAdminUsername
$tmpName = @'
ExchangeAdminUsername
'@ 
$tmpValue = "" 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #4 >> ExchangeSendOnBehalfMailboxSearchOU
$tmpName = @'
ExchangeSendOnBehalfMailboxSearchOU
'@ 
$tmpValue = @'
Enyoi.local/HelloID
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #5 >> ExchangeAuthentication
$tmpName = @'
ExchangeAuthentication
'@ 
$tmpValue = @'
kerberos
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #6 >> ExchangeSendOnBehalfUserSearchOU
$tmpName = @'
ExchangeSendOnBehalfUserSearchOU
'@ 
$tmpValue = @'
Enyoi.local/HelloID
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Exchange-On-Premises-SendOnBehalf-List-Mailboxes" #>
$tmpPsScript = @'
# used global defined variables in helloid
# $ExchangeConnectionUri
# $ExchangeAdminUsername
# $ExchangeAdminPassword
# $ExchangeAuthentication
# $ExchangeSendOnBehalfMailboxSearchOU

## connect to exchange and get list of mailboxes

try{
    $adminSecurePassword = ConvertTo-SecureString -String $ExchangeAdminPassword -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername,$adminSecurePassword
    $searchOUs = $ExchangeSendOnBehalfMailboxSearchOU  
    $searchValue = ($dataSource.SearchMailbox).trim()
    $searchQuery = "*$searchValue*"  

    $sessionOptionParams = @{
        SkipCACheck = $false
        SkipCNCheck = $false
        SkipRevocationCheck = $false
    }

    $sessionOption = New-PSSessionOption  @SessionOptionParams 

    $sessionParams = @{
        AllowRedirection = $true
        Authentication = $ExchangeAuthentication 
        ConfigurationName = 'Microsoft.Exchange' 
        ConnectionUri = $ExchangeConnectionUri 
        Credential = $adminCredential        
        SessionOption = $sessionOption       
    }

    $exchangeSession = New-PSSession @SessionParams

    Write-Information "Search query is '$searchQuery'" 
    Write-Information "Search OU is '$searchOUs'" 
    $getMailboxParams = @{
        RecipientTypeDetails = @('UserMailbox') 
        OrganizationalUnit =  $searchOUs 
        Filter = "Name -like '$searchQuery' -or DisplayName -like '$searchQuery' -or userPrincipalName -like '$searchQuery' -or Alias -like '$searchQuery'"   
    }
   
    
     $invokecommandParams = @{
        Session = $exchangeSession
        Scriptblock = [scriptblock] { Param ($Params)Get-Mailbox @Params}
        ArgumentList = $getMailboxParams
    }

    Write-Information "Successfully connected to Exchange '$ExchangeConnectionUri'"  
    
    $mailBoxes =  Invoke-Command @invokeCommandParams   

    $resultMailboxList = [System.Collections.Generic.List[PSCustomObject]]::New()
    foreach ($box in $mailBoxes)
    {        
       $resultMailbox = @{
        ExchangeGuid = $box.ExchangeGuid
        SamAccountName = $box.samAccountName     
        UserPrincipalName = $box.UserPrincipalName

       }
       $resultMailboxList.add($resultMailbox)

    }
    $resultMailboxList
    
    Remove-PSSession($exchangeSession)
  
} catch {
    Write-Error "Error connecting to Exchange using the URI '$exchangeConnectionUri', Message '$($_.Exception.Message)'"
}

'@ 
$tmpModel = @'
[{"key":"SamAccountName","type":0},{"key":"UserPrincipalName","type":0},{"key":"ExchangeGuid","type":0}]
'@ 
$tmpInput = @'
[{"description":"","translateDescription":false,"inputFieldType":1,"key":"SearchMailbox","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Exchange-On-Premises-SendOnBehalf-List-Mailboxes
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Exchange-On-Premises-SendOnBehalf-List-Mailboxes" #>

<# Begin: DataSource "Exchange-On-Premises-SendOnBehalf-Get-Users" #>
$tmpPsScript = @'
# used global defined variables in helloid
# $ExchangeConnectionUri
# $ExchangeAdminUsername
# $ExchangeAdminPassword
# $ExchangeAuthentication
# $ExchangeSendOnBehalfUserSearchOU  

## connect to exchange and get list of mailboxes

try{
    $adminSecurePassword = ConvertTo-SecureString -String $ExchangeAdminPassword -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername,$adminSecurePassword
    $searchOUs = $ExchangeSendOnBehalfUserSearchOU  
    $searchValue = ($dataSource.SearchUser).trim()
    $searchQuery = "*$searchValue*"   

    $sessionOptionParams = @{
        SkipCACheck = $false
        SkipCNCheck = $false
        SkipRevocationCheck = $false
    }

    $sessionOption = New-PSSessionOption  @SessionOptionParams 

    $sessionParams = @{
        AllowRedirection = $true
        Authentication = $ExchangeAuthentication 
        ConfigurationName = 'Microsoft.Exchange' 
        ConnectionUri = $ExchangeConnectionUri 
        Credential = $adminCredential        
        SessionOption = $sessionOption       
    }

    $exchangeSession = New-PSSession @SessionParams

    Write-Information "Search query is '$searchQuery'" 
    Write-Information "Search OU is '$searchOUs'" 

    $getUserParams = @{
        RecipientTypeDetails = @('Mailuser','user','UserMailbox')  
        OrganizationalUnit =  $searchOUs 
        Filter = "Name -like '$searchQuery' -or DisplayName -like '$searchQuery' -or userPrincipalName -like '$searchQuery'"   
    }
     $invokecommandParams = @{
        Session = $exchangeSession
        Scriptblock = [scriptblock] { Param ($Params)Get-User @Params}
        ArgumentList = $getUserParams
    }

    Write-Information "Successfully connected to Exchange '$ExchangeConnectionUri'"  
    
    $Users =  Invoke-Command @invokeCommandParams    

    $resultList = [System.Collections.Generic.List[PSCustomObject]]::New()
    foreach ($user in $Users) {
        if(![string]::IsNullOrEmpty($user.DisplayName)) {
            $DisplayName = $user.DisplayName
        }
        elseif (![string]::IsNullOrEmpty($user.userPrincipalName)) {
            $DisplayName = $user.userPrincipalName           
        }
        else {
            $DisplayName = $user.GUID
        }

        $result = @{  
            SamAccountName = $user.samAccountName      
            UserPrincipalName = $user.userPrincipalName
            GUID = $user.GUID
            DistinguishedName = $user.DistinguishedName   
            DisplayName = $DisplayName
            RecipientTypeDetails = $user.RecipientTypeDetails
        }
       $resultList.add($result)

    }
    $resultList
    Remove-PSSession($exchangeSession)
  
} catch {
    Write-Error "Error connecting to Exchange using the URI '$exchangeConnectionUri', Message '$($_.Exception.Message)'"
}

'@ 
$tmpModel = @'
[{"key":"DisplayName","type":0},{"key":"GUID","type":0},{"key":"DistinguishedName","type":0},{"key":"RecipientTypeDetails","type":0},{"key":"UserPrincipalName","type":0},{"key":"SamAccountName","type":0}]
'@ 
$tmpInput = @'
[{"description":"Search filter for user lookup","translateDescription":false,"inputFieldType":1,"key":"SearchUser","type":0,"options":1}]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
Exchange-On-Premises-SendOnBehalf-Get-Users
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "Exchange-On-Premises-SendOnBehalf-Get-Users" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Exchange on-premise - Manage send on behalf permissions" #>
$tmpSchema = @"
[{"label":"Select user","fields":[{"templateOptions":{},"type":"text","summaryVisibility":"Show","body":"Select the user that should aquire SendOnBehalf rights ","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"textSearchUser","templateOptions":{"label":"Search user","placeholder":"\u003cEnter search filter\u003e","required":true},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"User","templateOptions":{"label":"Users","required":true,"grid":{"columns":[{"headerName":"Display Name","field":"DisplayName"},{"headerName":"Sam Account Name","field":"SamAccountName"},{"headerName":"Distinguished Name","field":"DistinguishedName"},{"headerName":"GUID","field":"GUID"},{"headerName":"Recipient Type Details","field":"RecipientTypeDetails"},{"headerName":"User Principal Name","field":"UserPrincipalName"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[{"propertyName":"SearchUser","otherFieldValue":{"otherFieldKey":"textSearchUser"}}]}},"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]},{"label":"Select mailbox","fields":[{"templateOptions":{},"type":"text","summaryVisibility":"Show","body":"Select the mailbox account to be able to send on behalf of","requiresTemplateOptions":false,"requiresKey":false,"requiresDataSource":false},{"key":"textSeachMailbox","templateOptions":{"label":"Search Mailbox","placeholder":"\u003cEnter search filter\u003e","required":true},"type":"input","summaryVisibility":"Hide element","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"Mailbox","templateOptions":{"label":"Mailbox","required":true,"grid":{"columns":[{"headerName":"Sam Account Name","field":"SamAccountName"},{"headerName":"User Principal Name","field":"UserPrincipalName"},{"headerName":"Exchange Guid","field":"ExchangeGuid"}],"height":300,"rowSelection":"single"},"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"SearchMailbox","otherFieldValue":{"otherFieldKey":"textSeachMailbox"}}]}},"useFilter":true,"useDefault":false},"type":"grid","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":true}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange on-premise - Manage send on behalf permissions
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange on-premise - Manage send on behalf permissions
'@
$tmpTask = @'
{"name":"Exchange on-Premises - Manage SendOnBehalf Permissions","script":"$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# variables configured in form\r\n$mailboxGuid = $form.Mailbox.ExchangeGuid\r\n$mailboxUPN = $form.Mailbox.UserPrincipalName\r\n$userUPN = $form.User.UserPrincipalName\r\n$userGUID = $form.User.GUID\r\n\r\n# Connect to Exchange\r\ntry{\r\n    $adminSecurePassword = ConvertTo-SecureString -String \"$ExchangeAdminPassword\" -AsPlainText -Force\r\n    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername,$adminSecurePassword\r\n    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck\r\n    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -ErrorAction Stop \r\n    #-AllowRedirection\r\n    $session = Import-PSSession $exchangeSession -DisableNameChecking -AllowClobber\r\n    Write-Information \"Successfully connected to Exchange using the URI [$exchangeConnectionUri]\" \r\n    \r\n    $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange On-Premise\" # optional (free format text) \r\n            Message           = \"Successfully connected to Exchange using the URI [$exchangeConnectionUri]\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n        }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n} catch {\r\n    Write-Error \"Error connecting to Exchange using the URI [$exchangeConnectionUri]. Error: $($_.Exception.Message)\"\r\n    $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange On-Premise\" # optional (free format text) \r\n            Message           = \"Failed to connect to Exchange using the URI [$exchangeConnectionUri].\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n        }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\n\r\ntry{    \r\n    $SetUserParams = @{\r\n        identity = $mailboxGuid    \r\n        GrantSendOnBehalfTo = @{add=\"$userGUID\"}\r\n    }\r\n\r\n     $invokecommandParams = @{\r\n        Session = $exchangeSession\r\n        Scriptblock = [scriptblock] { Param ($Params)Set-Mailbox @Params}\r\n        ArgumentList = $SetUserParams\r\n    }\r\n   \r\n    $invokecommandParams   \r\n    $null =  Invoke-Command @invokeCommandParams -ErrorAction Stop     \r\n \r\n    Write-Information \"Succesfully granted SendOnBehalf right to user $userUPN [$userGUID] for mailbox $mailboxUPN [$mailboxGuid]\"\r\n    $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange On-Premise\" # optional (free format text) \r\n            Message           = \"Succesfully granted SendOnBehalf right to user $userUPN for mailbox $mailboxUPN.\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $mailboxUPN # optional (free format text) \r\n            TargetIdentifier  = [string]$mailboxGuid # optional (free format text) \r\n        }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log     \r\n    \r\n  \r\n} catch {\r\n   Write-Error \"Failed to grant SendOnBehalf right to user $userUPN for mailbox $mailboxUPN. Error: \u0027$($_.Exception.Message)\u0027\"\r\n   $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange On-Premise\" # optional (free format text) \r\n            Message           = \"Failed to grant SendOnBehalf right to user $userUPN for mailbox $mailboxUPN.\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $mailboxUPN # optional (free format text) \r\n            TargetIdentifier  = [string]$mailboxGuid # optional (free format text) \r\n        }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log  \r\n}\r\n\r\n# Disconnect from Exchange\r\ntry{\r\n    Remove-PsSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop\r\n    Write-Information \"Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]\"     \r\n    $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange On-Premise\" # optional (free format text) \r\n            Message           = \"Successfully disconnected from Exchange using the URI [$exchangeConnectionUri]\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n        }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n} catch {\r\n    Write-Error \"Error disconnecting from Exchange.  Error: $($_.Exception.Message)\"\r\n    $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"Exchange On-Premise\" # optional (free format text) \r\n            Message           = \"Failed to disconnect from Exchange using the URI [$exchangeConnectionUri].\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $exchangeConnectionUri # optional (free format text) \r\n            TargetIdentifier  = $([string]$session.GUID) # optional (free format text) \r\n        }\r\n    #send result back  \r\n    Write-Information -Tags \"Audit\" -MessageData $log\r\n}\r\n\u003c#----- Exchange On-Premises: End -----#\u003e","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-file-text-o" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>


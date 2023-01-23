# used global defined variables in helloid
# $ExchangeConnectionUri
# $ExchangeAdminUsername
# $ExchangeAdminPassword
# $ExchangeAuthentication
# $ExchangeSendOnBehalfUserSearchOU  

## connect to exchange and get list of mailboxes

try{
    $adminSecurePassword = ConvertTo-SecureString -String $ExchangeAdminPassword -AsPlainText -Force
    $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername,$adminSecurePassword)
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


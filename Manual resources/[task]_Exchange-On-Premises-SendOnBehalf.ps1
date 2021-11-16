# used global defined variables in helloid
# $ExchangeConnectionUri
# $ExchangeAdminUsername
# $ExchangeAdminPassword
# $ExchangeAuthentication

## connect to exchange and get list of mailboxes

try{
    $adminSecurePassword = ConvertTo-SecureString -String $ExchangeAdminPassword -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername,$adminSecurePassword

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
     HID-Write-Status -Message "Successfully connected to Exchange '$ExchangeConnectionUri'" -Event Information

    $SetUserParams = @{
        identity = $mailboxGuid    
        GrantSendOnBehalfTo = @{add="$userGUID"}
    }

     $invokecommandParams = @{
        Session = $exchangeSession
        Scriptblock = [scriptblock] { Param ($Params)Set-Mailbox @Params}
        ArgumentList = $SetUserParams
    }

   
    $invokecommandParams   
    $null =  Invoke-Command @invokeCommandParams        
 
    HID-Write-Status -Message "Succesfully granted SendOnBehalf right to user $userUPN [$userGUID] for mailbox $mailboxUPN [$mailboxGuid]" -Event Success
    HID-Write-Summary -Message "Succesfully granted SendOnBehalf right to user $userUPN for mailbox $mailboxUPN" -Event Success   
    
    Remove-PSSession($exchangeSession)
  
} catch {
    HID-Write-Status "Error connecting to Exchange using the URI '$exchangeConnectionUri', Message: '$($_.Exception.Message)'" -Event Error
    HID-Write-Summary -Message "Failed to grant  SendOnBehalf right to user $userUPN for mailbox $mailboxUPN "  -Event Failed
}


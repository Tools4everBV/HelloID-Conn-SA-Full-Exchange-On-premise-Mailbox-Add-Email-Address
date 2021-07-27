<#-----[task]_Exchange-mailbox-add-email-address-----#>
# Connect to Exchange
try {
    $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername, $adminSecurePassword
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck #-SkipRevocationCheck
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -Authentication Kerberos -ErrorAction Stop #-AllowRedirection
    HID-Write-Status -Message "Successfully connected to Exchange using the URI [$exchangeConnectionUri]" -Event Success
} catch {
    HID-Write-Status -Message "Error connecting to Exchange using the URI [$exchangeConnectionUri]" -Event Error
    HID-Write-Status -Message "Error at line: $($_.InvocationInfo.ScriptLineNumber - 79): $($_.Exception.Message)" -Event Error
    if ($debug -eq $true) {
        HID-Write-Status -Message "$($_.Exception)" -Event Error
    }
    HID-Write-Summary -Message "Failed to connect to Exchange using the URI [$exchangeConnectionUri]" -Event Failed
    throw $_
}

try {
    $ParamsSetMailbxox = @{
        Identity       = $UserPrincipalName
        EmailAddresses = @{add = "$newEmailAddress" }
    }
    $null = Invoke-Command -Session $exchangeSession -ScriptBlock {
        Param ($ParamsSetMailbxox)
        Set-Mailbox @ParamsSetMailbxox
    } -ArgumentList $ParamsSetMailbxox

    HID-Write-Status -Message "Successfully added emailaddress [$newEmailAddress] for [$UserPrincipalName]" -Event Success
    HID-Write-Summary -Message "Successfully added emailaddress [$newEmailAddress] for [$UserPrincipalName]" -Event Success
} catch {
    HID-Write-Status -Message "Error adding emailaddress [$newEmailAddress] for [$UserPrincipalName]" -Event Error
    throw $_
}

# Disconnect from Exchange
try {
    Remove-PSSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
    HID-Write-Status -Message "Successfully disconnected from Exchange" -Event Success
} catch {
    HID-Write-Status -Message "Error disconnecting from Exchange" -Event Error
    HID-Write-Status -Message "Error at line: $($_.InvocationInfo.ScriptLineNumber - 79): $($_.Exception.Message)" -Event Error
    if ($debug -eq $true) {
        HID-Write-Status -Message "$($_.Exception)" -Event Error
    }
    HID-Write-Summary -Message "Failed to disconnect from Exchange" -Event Failed
    throw $_
}
<#----- Exchange On-Premises: End -----#>


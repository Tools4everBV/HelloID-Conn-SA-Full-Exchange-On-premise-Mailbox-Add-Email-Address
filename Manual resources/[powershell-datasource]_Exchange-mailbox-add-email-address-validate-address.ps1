<#----- [powershell-datasource]_Exchange-mailbox-add-email-address-validate-address -----#>
# Connect to Exchange
try {
    $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
    $adminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ExchangeAdminUsername, $adminSecurePassword
    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck #-SkipRevocationCheck
    $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeConnectionUri -Credential $adminCredential -SessionOption $sessionOption -Authentication Kerberos -ErrorAction Stop #-AllowRedirection

    Write-Information "Successfully connected to Exchange using the URI [$exchangeConnectionUri]"
} catch {
    Write-Information  "Error connecting to Exchange using the URI [$exchangeConnectionUri]"
    Write-Error -Message "$($_.Exception.Message)"
    Write-Information "Failed to connect to Exchange using the URI [$exchangeConnectionUri]"
    throw $_
}

try {
    $searchValue = $dataSource.newEmail
    $searchQuery = "*$searchValue*"
    # $searchOUs = $ADsharedMailboxSearchOU


    if ([String]::IsNullOrEmpty($searchValue) -eq $true) {
        Write-Information "No Searchvalue"
        return
    } else {
        Write-Information "SearchQuery: [EmailAddresses -like '$searchQuery]"

        #filter to get only the emailaddres from the search bar
        # $ParamsGetMailbxox = @{
        #     Filter = "{EmailAddresses -like '$searchQuery'}"
        # }
        # $mailBoxes = Invoke-Command -Session $exchangeSession -ScriptBlock {
        #     Param ($ParamsGetMailbxox)
        #     Get-Recipient @ParamsGetMailbxox
        # } -ArgumentList $ParamsGetMailbxox

        $mailBoxes = Invoke-Command -Session $exchangeSession -ScriptBlock {
            Get-Recipient # get all mailboxes, to avoid duplicate mailadresses in the loop below (Finding a unique mail address)
        }
        $mailBoxes = $mailboxes | Select-Object Name, EmailAddresses -ExpandProperty EmailAddresses | ForEach-Object { $_ -replace "smtp:", "" }

        if ($searchValue -notin $mailBoxes) {
            Write-Information "New mailbox: $searchValue is Unique"
            $UniqueMailAddress = $searchValue
        } else {
            $amountOfTries = 10
            Write-Information "Trying to find a unique alternative address with a followup number"
            for ($i = 1; $i -lt $amountOfTries; $i++) {
                $searchName = $searchValue.split("@")[0]
                $searchDomain = $searchValue.split("@")[1]

                if (( $searchName + $i + "@" + $searchDomain ) -notin $mailBoxes) {
                    $UniqueMailAddress = $searchName + $i + "@" + $searchDomain
                    Write-Information $UniqueMailAddress
                    break
                }
            }
        }
        Write-Information "Unique mailaddress found: $UniqueMailAddress"
        Write-Output   @{NewEMailAddress = $UniqueMailAddress }
    }
} catch {
    $msg = "Error searching for unique mailaddress [$searchValue]. Error: $($_.Exception.Message)"
    Write-Error $msg
}

# Disconnect from Exchange
try {
    Remove-PSSession -Session $exchangeSession -Confirm:$false -ErrorAction Stop
    Write-Information "Successfully disconnected from Exchange"
} catch {
    Write-Error -Message "Error disconnecting from Exchange"
    Write-Error -Message "$($_.Exception.Message)"
    Write-Error -Message "Failed to disconnect from Exchange"
    throw $_
}
<#----- Exchange On-Premises: End -----#>


param(
    [string]$UserPrincipalName,
    [bool]$ShowBanner = $true
)

$connectParams = @{ ShowBanner = $ShowBanner }
if ($UserPrincipalName) {
    $connectParams.UserPrincipalName = $UserPrincipalName
}

Connect-ExchangeOnline @connectParams
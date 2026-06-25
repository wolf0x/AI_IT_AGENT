#Requires -Modules ExchangeOnlineManagement
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][datetime]$StartDateUtc,
  [Parameter(Mandatory=$true)][datetime]$EndDateUtc,
  [string]$SenderAddress,
  [string]$RecipientAddress,
  [Parameter(Mandatory=$true)][string]$OutputCsv,
  [string]$UserPrincipalNameForConnect,
  [string]$TranscriptPath
)

$ErrorActionPreference = "Stop"
$runId = [guid]::NewGuid().ToString()
$collectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")

if ($TranscriptPath) { Start-Transcript -Path $TranscriptPath -Append | Out-Null }

try {
  . "$PSScriptRoot/connect-exo.ps1" -UserPrincipalName $UserPrincipalNameForConnect -ShowBanner:$false

  $params = @{
    StartDate = $StartDateUtc
    EndDate   = $EndDateUtc
    PageSize  = 5000
  }
  if ($SenderAddress)    { $params["SenderAddress"] = $SenderAddress }
  if ($RecipientAddress) { $params["RecipientAddress"] = $RecipientAddress }

  $traces = Get-MessageTrace @params

  $rows = foreach ($t in $traces) {
    [pscustomobject]@{
      RunId=$runId
      CollectedAtUtc=$collectedAtUtc
      MessageTraceId=$t.MessageTraceId
      Received=$t.Received
      SenderAddress=$t.SenderAddress
      RecipientAddress=$t.RecipientAddress
      Subject=$t.Subject
      Status=$t.Status
      Size=$t.Size
      FromIP=$t.FromIP
      ToIP=$t.ToIP
    }
  }

  $rows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
} finally {
  try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
  if ($TranscriptPath) { Stop-Transcript | Out-Null }
}
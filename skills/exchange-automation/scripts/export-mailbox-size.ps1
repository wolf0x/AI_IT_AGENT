#Requires -Modules ExchangeOnlineManagement
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$OutputCsv,
  [string[]]$Identity,
  [ValidateSet("UserMailbox","SharedMailbox","RoomMailbox","EquipmentMailbox","All")]
  [string]$Type = "All",
  [string]$UserPrincipalNameForConnect,
  [string]$TranscriptPath
)

$ErrorActionPreference = "Stop"
$runId = [guid]::NewGuid().ToString()
$collectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")

if ($TranscriptPath) { Start-Transcript -Path $TranscriptPath -Append | Out-Null }

try {
  . "$PSScriptRoot/connect-exo.ps1" -UserPrincipalName $UserPrincipalNameForConnect -ShowBanner:$false

  $mailboxes =
    if ($Identity -and $Identity.Count -gt 0) {
      foreach ($id in $Identity) { Get-EXOMailbox -Identity $id -PropertySets Minimum }
    } else {
      if ($Type -eq "All") { Get-EXOMailbox -ResultSize Unlimited -PropertySets Minimum }
      else { Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $Type -PropertySets Minimum }
    }

  $rows = foreach ($mbx in $mailboxes) {
    $stats = $null
    try { $stats = Get-EXOMailboxStatistics -Identity $mbx.Identity } catch { }

    $archiveStats = $null
    try { $archiveStats = Get-EXOMailboxStatistics -Identity $mbx.Identity -Archive } catch { }

    [pscustomobject]@{
      RunId               = $runId
      CollectedAtUtc      = $collectedAtUtc
      Identity            = $mbx.Identity
      UserPrincipalName   = $mbx.UserPrincipalName
      RecipientTypeDetails= $mbx.RecipientTypeDetails
      PrimarySmtpAddress  = $mbx.PrimarySmtpAddress
      DisplayName         = $mbx.DisplayName
      ItemCount           = $stats.ItemCount
      TotalItemSize       = $stats.TotalItemSize
      TotalDeletedItemSize= $stats.TotalDeletedItemSize
      ArchiveStatus       = $mbx.ArchiveStatus
      ArchiveName         = $mbx.ArchiveName
      ArchiveItemCount    = $archiveStats.ItemCount
      ArchiveTotalItemSize= $archiveStats.TotalItemSize
      IsInactiveMailbox   = $mbx.IsInactiveMailbox
      Notes               = ""
    }
  }

  $rows | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
} finally {
  try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
  if ($TranscriptPath) { Stop-Transcript | Out-Null }
}
#Requires -Modules ExchangeOnlineManagement
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$OutputCsv,
  [Parameter(Mandatory=$true)][string[]]$MailboxIdentity,
  [string]$UserPrincipalNameForConnect,
  [string]$TranscriptPath
)

$ErrorActionPreference = "Stop"
$runId = [guid]::NewGuid().ToString()
$collectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")

if ($TranscriptPath) { Start-Transcript -Path $TranscriptPath -Append | Out-Null }

try {
  . "$PSScriptRoot/connect-exo.ps1" -UserPrincipalName $UserPrincipalNameForConnect -ShowBanner:$false

  $all = New-Object System.Collections.Generic.List[object]

  foreach ($mbxId in $MailboxIdentity) {
    $mbx = Get-EXOMailbox -Identity $mbxId -PropertySets Minimum
    $mbxSmtp = $mbx.PrimarySmtpAddress

    # Full Access
    foreach ($p in (Get-MailboxPermission -Identity $mbx.Identity)) {
      if ($p.User -and $p.User.ToString() -notmatch "NT AUTHORITY\\SELF") {
        $all.Add([pscustomobject]@{
          RunId=$runId; CollectedAtUtc=$collectedAtUtc
          Mailbox=$mbx.Identity; MailboxPrimarySmtp=$mbxSmtp
          PermissionType="FullAccess"
          GrantedTo=$p.User
          GrantedToPrimarySmtp=""
          AccessRights=($p.AccessRights -join ";")
          IsInherited=$p.IsInherited
          Deny=$p.Deny
          Notes=""
        })
      }
    }

    # Send As
    foreach ($rp in (Get-RecipientPermission -Identity $mbx.Identity -ErrorAction SilentlyContinue)) {
      if ($rp.Trustee) {
        $all.Add([pscustomobject]@{
          RunId=$runId; CollectedAtUtc=$collectedAtUtc
          Mailbox=$mbx.Identity; MailboxPrimarySmtp=$mbxSmtp
          PermissionType="SendAs"
          GrantedTo=$rp.Trustee
          GrantedToPrimarySmtp=""
          AccessRights=($rp.AccessRights -join ";")
          IsInherited=""
          Deny=""
          Notes=""
        })
      }
    }

    # Send on Behalf (property on mailbox)
    foreach ($sob in ($mbx.GrantSendOnBehalfTo)) {
      $all.Add([pscustomobject]@{
        RunId=$runId; CollectedAtUtc=$collectedAtUtc
        Mailbox=$mbx.Identity; MailboxPrimarySmtp=$mbxSmtp
        PermissionType="SendOnBehalf"
        GrantedTo=$sob
        GrantedToPrimarySmtp=""
        AccessRights="SendOnBehalf"
        IsInherited=""
        Deny=""
        Notes=""
      })
    }
  }

  $all | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
} finally {
  try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
  if ($TranscriptPath) { Stop-Transcript | Out-Null }
}
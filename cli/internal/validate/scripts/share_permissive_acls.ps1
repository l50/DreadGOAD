# Share permissive ACL probe — scans share roots populated by the
# vulns_permissions role for ACEs that grant Modify/Write/FullControl to
# permissive principals (Everyone / Authenticated Users / IIS_IUSRS / Users).
# The role lays these ACLs down so non-privileged accounts can drop content.
#
# Share roots are discovered via Get-SmbShare rather than hardcoded. Variant
# labs randomize share names (upstream's "thewall" becomes e.g. "contracts"),
# so a fixed path list would silently scan nothing and report a clean result.
# C:\inetpub\wwwroot\upload is appended explicitly: it is an ACL target that
# the role creates but never publishes as a share.
#
# Output:
#   { "entries": [ { "path": string, "identity": string,
#                    "rights": string } ],
#     "error": string|null }

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$result = [ordered]@{ entries = @(); error = $null }

try {
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($share in @(Get-SmbShare -ErrorAction SilentlyContinue)) {
        # Skip administrative shares (C$, ADMIN$, IPC$); their ACLs are not
        # what the vulns_permissions role manipulates.
        if ($share.Name -match '\$$') { continue }
        if ($share.Path) { $paths.Add($share.Path) }
    }
    $paths.Add('C:\inetpub\wwwroot\upload')

    $entries = @()
    foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }
        $acl = Get-Acl -Path $p -ErrorAction SilentlyContinue
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match 'Everyone|Authenticated Users|IIS_IUSRS|Users' -and
                $ace.FileSystemRights -match 'FullControl|Modify|Write') {
                $entries += [ordered]@{
                    path     = $p
                    identity = "$($ace.IdentityReference)"
                    rights   = "$($ace.FileSystemRights)"
                }
            }
        }
    }
    $result.entries = @($entries)
} catch {
    $result.error = "$_"
}

Write-Output '===BEGIN_JSON==='
$result | ConvertTo-Json -Compress -Depth 5
Write-Output '===END_JSON==='

<#
.SYNOPSIS
  NullOut Shipcheck — end-to-end stdio MCP verification.

.DESCRIPTION
  Starts the NullOut MCP server as a subprocess, speaks JSON-RPC over stdio,
  and verifies all critical invariants:
    1) tools/list works
    2) roots are read + scoped
    3) scan→plan→delete works for a hazardous file (reserved device name)
    4) delete refuses without token
    5) empty-only directory rule works (empty dir with trailing dot)
    6) non-empty directory refused (trailing space dir with child)
    7) deny_all reparse rule (best-effort; skip if junction can't be created)

  Fixtures must be hazardous because scan_reserved_names only returns flagged entries.
  Uses extended-path prefix (\\?\) to create reserved/trailing-dot/space names on NTFS.

.PARAMETER Python
  Python executable. Default: python

.PARAMETER ServerModule
  Module to run. Default: nullout.server

.PARAMETER TimeoutMs
  JSON-RPC read timeout in milliseconds. Default: 8000
#>

param(
  [string]$Python = "python",
  [string]$ServerModule = "nullout.server",
  [int]$TimeoutMs = 8000
)

$ErrorActionPreference = "Stop"

# --- Helpers ---

function New-ShipcheckRoot {
  $p = Join-Path $env:TEMP ("nullout-shipcheck-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $p | Out-Null
  return $p
}

function Write-JsonLine([System.IO.StreamWriter]$writer, $obj) {
  $line = ($obj | ConvertTo-Json -Compress -Depth 20)
  $writer.WriteLine($line)
  $writer.Flush()
}

function Read-JsonLine([System.IO.StreamReader]$reader, [int]$timeoutMs) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
    if ($reader.Peek() -ge 0) {
      $line = $reader.ReadLine()
      if ($null -ne $line -and $line.Trim().Length -gt 0) {
        return ($line | ConvertFrom-Json -Depth 20)
      }
    }
    Start-Sleep -Milliseconds 25
  }
  throw "Timed out waiting for JSON-RPC response after ${timeoutMs}ms"
}

function Rpc-Call([System.IO.StreamWriter]$writer, [System.IO.StreamReader]$reader,
                  [string]$method, $params, [int]$id) {
  $req = @{
    jsonrpc = "2.0"
    id      = $id
    method  = $method
    params  = $params
  }
  Write-JsonLine $writer $req
  $resp = Read-JsonLine $reader $TimeoutMs
  if ($resp.id -ne $id) { throw "Mismatched response id. Expected $id, got $($resp.id)" }
  return $resp
}

# --- Setup ---

$root = New-ShipcheckRoot
$env:NULLOUT_ROOTS = $root
$env:NULLOUT_TOKEN_SECRET = "shipcheck-not-a-real-secret"

Write-Host "== NullOut Shipcheck =="
Write-Host "Root: $root"
Write-Host ""

# --- Create hazardous fixtures using Python + extended-path prefix ---
# These MUST trigger hazard detection because scan_reserved_names only returns flagged entries.
# We use Python (not .NET) because .NET normalizes trailing dots/spaces even with \\?\ prefix.

$fixtureHelper = Join-Path $PSScriptRoot "create_fixtures.py"
if (-not (Test-Path $fixtureHelper)) {
  throw "Cannot find create_fixtures.py at $fixtureHelper"
}

& $Python $fixtureHelper $root
if ($LASTEXITCODE -ne 0) { throw "Failed to create hazardous fixtures" }

$extRoot = "\\?\$root"
$nulFile = "$extRoot\NUL.txt"
$emptyDotDir = "$extRoot\emptydir."
$nonEmptySpaceDir = "$extRoot\notempty "

# 4. Best-effort: junction (reparse point)
$reparseCreated = $false
$junctionPath = Join-Path $root "junction_link"
$junctionTarget = Join-Path $root "junction_target"
try {
  New-Item -ItemType Directory -Force -Path $junctionTarget | Out-Null
  $mkResult = cmd /c "mklink /J `"$junctionPath`" `"$junctionTarget`"" 2>&1
  if (Test-Path $junctionPath) { $reparseCreated = $true }
} catch {
  $reparseCreated = $false
}

# --- Start server subprocess ---

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Python
$psi.Arguments = "-m $ServerModule"
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi

if (-not $p.Start()) { throw "Failed to start server: $Python -m $ServerModule" }

$writer = $p.StandardInput
$reader = $p.StandardOutput
$stderr = $p.StandardError

$passed = 0
$total  = 8

try {
  $id = 1

  # [1/8] tools/list
  Write-Host "[1/$total] tools/list"
  $resp = Rpc-Call $writer $reader "tools/list" @{} $id; $id++
  if ($null -eq $resp.result.tools) { throw "tools/list returned no tools" }
  $toolNames = $resp.result.tools | ForEach-Object { $_.name }
  Write-Host "  tools: $($toolNames -join ', ')"
  $passed++

  # [2/8] list_allowed_roots
  Write-Host "[2/$total] list_allowed_roots"
  $resp = Rpc-Call $writer $reader "list_allowed_roots" @{} $id; $id++
  $roots = $resp.result.result.roots
  if ($roots.Count -lt 1) { throw "No allowlisted roots returned (check NULLOUT_ROOTS)" }
  $rootId = $roots[0].rootId
  Write-Host "  rootId=$rootId  path=$($roots[0].path)"
  $passed++

  # [3/8] scan_reserved_names
  Write-Host "[3/$total] scan_reserved_names"
  $resp = Rpc-Call $writer $reader "scan_reserved_names" @{
    rootId     = $rootId
    recursive  = $true
    maxDepth   = 10
    includeDirs = $true
  } $id; $id++

  $scanResult = $resp.result.result
  $findings   = $scanResult.findings
  Write-Host "  visited=$($scanResult.stats.visited)  flagged=$($scanResult.stats.flagged)  reparse_skipped=$($scanResult.stats.skippedReparsePoints)"
  foreach ($f in $findings) {
    $hcodes = ($f.hazards | ForEach-Object { $_.code }) -join ", "
    Write-Host "  finding: rel='$($f.relativePath)'  type=$($f.entryType)  hazards=[$hcodes]"
  }

  # Locate findings by relativePath
  function Find-ByRel($rel) {
    foreach ($f in $findings) { if ($f.relativePath -eq $rel) { return $f } }
    return $null
  }

  $fileFinding = Find-ByRel "NUL.txt"
  if ($null -eq $fileFinding) { throw "Scan did not flag NUL.txt (WIN_RESERVED_DEVICE_BASENAME)" }

  $emptyDirFinding = Find-ByRel "emptydir."
  if ($null -eq $emptyDirFinding) { throw "Scan did not flag emptydir. (WIN_TRAILING_DOT_SPACE)" }

  $nonEmptyDirFinding = Find-ByRel "notempty "
  if ($null -eq $nonEmptyDirFinding) { throw "Scan did not flag 'notempty ' (WIN_TRAILING_DOT_SPACE)" }

  $reparseFinding = $null
  if ($reparseCreated) {
    $reparseFinding = Find-ByRel "junction_link"
    if ($null -eq $reparseFinding) {
      Write-Host "  (junction created but not returned as finding; will skip reparse assertion)"
    }
  } else {
    Write-Host "  (junction not created; skipping reparse checks)"
  }
  $passed++

  # [4/8] delete_entry without token should fail
  Write-Host "[4/$total] delete_entry without valid token should fail"
  $resp = Rpc-Call $writer $reader "delete_entry" @{
    findingId    = $fileFinding.findingId
    confirmToken = "bogus-token-not-valid"
  } $id; $id++
  if ($resp.result.ok -ne $false) { throw "Expected failure without valid token, got ok" }
  if ($resp.result.error.code -ne "E_CONFIRM_TOKEN_INVALID") {
    throw "Expected E_CONFIRM_TOKEN_INVALID, got $($resp.result.error.code)"
  }
  $passed++

  # [5/8] plan_cleanup for all three fixtures
  Write-Host "[5/$total] plan_cleanup"
  $resp = Rpc-Call $writer $reader "plan_cleanup" @{
    findingIds       = @($fileFinding.findingId, $emptyDirFinding.findingId, $nonEmptyDirFinding.findingId)
    requestedActions = @("DELETE")
  } $id; $id++
  if ($resp.result.ok -ne $true) { throw "plan_cleanup failed: $($resp.result | ConvertTo-Json -Depth 5)" }
  $entries = $resp.result.result.entries
  if ($entries.Count -ne 3) { throw "Expected 3 plan entries, got $($entries.Count)" }

  function Token-For($fid) {
    foreach ($e in $entries) { if ($e.findingId -eq $fid) { return $e.confirmToken } }
    return $null
  }

  $fileToken       = Token-For $fileFinding.findingId
  $emptyToken      = Token-For $emptyDirFinding.findingId
  $nonEmptyToken   = Token-For $nonEmptyDirFinding.findingId
  $passed++

  # [6/8] delete file (NUL.txt — should succeed)
  Write-Host "[6/$total] delete NUL.txt (reserved device name)"
  $resp = Rpc-Call $writer $reader "delete_entry" @{
    findingId    = $fileFinding.findingId
    confirmToken = $fileToken
  } $id; $id++
  if ($resp.result.ok -ne $true) { throw "Expected NUL.txt delete success: $($resp.result | ConvertTo-Json -Depth 5)" }
  $passed++

  # [7/8] delete empty directory (emptydir. — should succeed)
  Write-Host "[7/$total] delete emptydir. (empty dir, trailing dot)"
  $resp = Rpc-Call $writer $reader "delete_entry" @{
    findingId    = $emptyDirFinding.findingId
    confirmToken = $emptyToken
  } $id; $id++
  if ($resp.result.ok -ne $true) { throw "Expected emptydir. delete success: $($resp.result | ConvertTo-Json -Depth 5)" }
  $passed++

  # [8/8] delete non-empty directory (notempty  — should fail E_DIR_NOT_EMPTY)
  Write-Host "[8/$total] delete 'notempty ' (non-empty dir, trailing space) should fail"
  $resp = Rpc-Call $writer $reader "delete_entry" @{
    findingId    = $nonEmptyDirFinding.findingId
    confirmToken = $nonEmptyToken
  } $id; $id++
  if ($resp.result.ok -ne $false) { throw "Expected non-empty directory delete failure" }
  if ($resp.result.error.code -ne "E_DIR_NOT_EMPTY") {
    throw "Expected E_DIR_NOT_EMPTY, got $($resp.result.error.code)"
  }
  $passed++

  # Optional: reparse delete assertion
  if ($null -ne $reparseFinding) {
    Write-Host "  [bonus] reparse delete should fail E_REPARSE_POLICY_BLOCKED"
    $resp2 = Rpc-Call $writer $reader "plan_cleanup" @{
      findingIds       = @($reparseFinding.findingId)
      requestedActions = @("DELETE")
    } $id; $id++
    $rtok = $resp2.result.result.entries[0].confirmToken
    $resp3 = Rpc-Call $writer $reader "delete_entry" @{
      findingId    = $reparseFinding.findingId
      confirmToken = $rtok
    } $id; $id++
    if ($resp3.result.ok -ne $false -or $resp3.result.error.code -ne "E_REPARSE_POLICY_BLOCKED") {
      throw "Expected E_REPARSE_POLICY_BLOCKED for junction delete"
    }
    Write-Host "  reparse deny_all confirmed"
  }

  Write-Host ""
  Write-Host "Shipcheck PASSED ($passed/$total)"

} finally {
  try { $writer.Close() } catch {}
  try { $reader.Close() } catch {}
  try {
    if (-not $p.HasExited) { $p.Kill() }
  } catch {}
  try {
    $errText = $stderr.ReadToEnd()
    if ($errText.Trim().Length -gt 0) {
      Write-Host ""
      Write-Host "---- Server stderr ----"
      Write-Host $errText
      Write-Host "-----------------------"
    }
  } catch {}
}

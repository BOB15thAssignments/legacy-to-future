<#
.SYNOPSIS
    Build the shimforge self-test rig with clang / lld-link.

.DESCRIPTION
    Produces, under selftest\build\ :

        oldlib.dll  oldlib.lib     v1 ABI (the behaviour under preservation)
        newlib.dll  newlib.lib     v2 ABI
        app.exe                    v1 consumer
        shim_ok.dll                correct v1-on-v2 adapter
        shim_bug_offset.dll        adapters with one planted defect each
        shim_bug_callback.dll
        shim_bug_handle.dll
        shim_bug_ptr.dll

        run\old\          app.exe + the real oldlib.dll
        run\ok\           app.exe + shim_ok.dll renamed oldlib.dll + newlib.dll
        run\bug_*\        the same with each buggy shim

    Export ordinals (including the NONAME at 8) come from generated .def files
    rather than __declspec(dllexport), so every implementation presents a
    byte-identical export directory shape and the structural oracle check has
    something exact to compare.

    No MSVC, no cmake: clang drives lld-link directly.
#>
[CmdletBinding()]
param(
    [string]$Clang = "C:\Program Files\LLVM\bin\clang.exe",
    [switch]$Clean,
    [switch]$NoWerror
)

$ErrorActionPreference = "Stop"

$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $here "build"
$runs  = Join-Path $build "run"

if (-not (Test-Path $Clang)) {
    throw "clang not found at '$Clang' (pass -Clang <path>)"
}

if ($Clean -and (Test-Path $build)) {
    Remove-Item -Recurse -Force $build
}
New-Item -ItemType Directory -Force $build | Out-Null
New-Item -ItemType Directory -Force $runs  | Out-Null

$cflags = @("-Wall", "-Wextra", "-O1")
if (-not $NoWerror) { $cflags += "-Werror" }

function Write-Def {
    param([string]$Name, [string[]]$Lines)
    $path = Join-Path $build $Name
    Set-Content -Path $path -Value $Lines -Encoding ascii
    return $path
}

function Invoke-Clang {
    # Not named $Args: that is an automatic variable and splatting it silently
    # passes nothing.
    param([string]$What, [string[]]$ClangArgs)
    Write-Host "  $What"
    & $Clang @ClangArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (clang exit $LASTEXITCODE)"
    }
}

# The v1 surface. Version sits at ordinal 8 with no name so the rig exercises
# ordinal-only resolution end to end.
$v1Exports = @(
    "LIBRARY oldlib",
    "EXPORTS",
    "    Init        @1",
    "    Open        @2",
    "    SetCallback @3",
    "    Process     @4",
    "    Read        @5",
    "    GetStats    @6",
    "    Close       @7",
    "    Version     @8 NONAME"
)

$oldDef  = Write-Def "oldlib.def" $v1Exports
# Same surface, same ordinals: a shim is only a drop-in if the export
# directory matches, so it shares the v1 def verbatim.
$shimDef = Write-Def "shim.def"   $v1Exports
$newDef  = Write-Def "newlib.def" @(
    "LIBRARY newlib",
    "EXPORTS",
    "    Init2        @1",
    "    Open2        @2",
    "    SetCallback2 @3",
    "    Process2     @4",
    "    Read2        @5",
    "    GetStats2    @6",
    "    Close2       @7",
    "    Version2     @8"
)

Write-Host "[build] libraries"
Invoke-Clang "oldlib.dll" (@("-shared") + $cflags + @(
    "-o", (Join-Path $build "oldlib.dll"),
    (Join-Path $here "oldlib.c"),
    "-Wl,/DEF:$oldDef",
    "-Wl,/IMPLIB:$(Join-Path $build 'oldlib.lib')"
))
Invoke-Clang "newlib.dll" (@("-shared") + $cflags + @(
    "-o", (Join-Path $build "newlib.dll"),
    (Join-Path $here "newlib.c"),
    "-Wl,/DEF:$newDef",
    "-Wl,/IMPLIB:$(Join-Path $build 'newlib.lib')"
))

Write-Host "[build] shims"
foreach ($shim in @("shim_ok", "shim_bug_offset", "shim_bug_callback", "shim_bug_handle", "shim_bug_ptr")) {
    Invoke-Clang "$shim.dll" (@("-shared") + $cflags + @(
        "-o", (Join-Path $build "$shim.dll"),
        (Join-Path $here "$shim.c"),
        (Join-Path $build "newlib.lib"),
        "-Wl,/DEF:$shimDef"
    ))
}

Write-Host "[build] app"
Invoke-Clang "app.exe" ($cflags + @(
    "-o", (Join-Path $build "app.exe"),
    (Join-Path $here "app.c"),
    (Join-Path $build "oldlib.lib")
))

# Each implementation gets its own directory because the app resolves
# oldlib.dll from its own folder; that is the whole substitution mechanism.
Write-Host "[build] staging run directories"
$stage = @{
    "old"          = "oldlib.dll"
    "ok"           = "shim_ok.dll"
    "bug_offset"   = "shim_bug_offset.dll"
    "bug_callback" = "shim_bug_callback.dll"
    "bug_handle"   = "shim_bug_handle.dll"
    "bug_ptr"      = "shim_bug_ptr.dll"
}
foreach ($name in $stage.Keys) {
    $dir = Join-Path $runs $name
    New-Item -ItemType Directory -Force $dir | Out-Null
    Copy-Item (Join-Path $build "app.exe") (Join-Path $dir "app.exe") -Force
    Copy-Item (Join-Path $build $stage[$name]) (Join-Path $dir "oldlib.dll") -Force
    if ($name -ne "old") {
        Copy-Item (Join-Path $build "newlib.dll") (Join-Path $dir "newlib.dll") -Force
    }
    Write-Host "  run\$name  <- $($stage[$name])"
}

Write-Host "[build] ok -> $build"

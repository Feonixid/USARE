$BaseDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$VenvPython = Join-Path -Path $BaseDir -ChildPath ".venv\Scripts\python.exe"
$ScriptPath = Join-Path -Path $BaseDir -ChildPath "usare.py"

if (Test-Path -Path $VenvPython) {
    & $VenvPython $ScriptPath @args
} else {
    & python $ScriptPath @args
}

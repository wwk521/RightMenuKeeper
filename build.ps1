$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$projectDir = $PSScriptRoot
if (-not (Test-Path -LiteralPath $compiler)) { throw '未找到 Windows .NET Framework C# 编译器。' }
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /utf8output "/win32manifest:$projectDir\app.manifest" "/out:$projectDir\右键菜单管家.exe" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.Core.dll "$projectDir\RightMenuKeeper.cs"
if ($LASTEXITCODE -ne 0) { throw '编译失败。' }
Write-Output "已生成：$projectDir\右键菜单管家.exe"

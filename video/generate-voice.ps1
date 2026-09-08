$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Speech
$out = Join-Path (Get-Location) 'public'
New-Item -ItemType Directory -Force $out | Out-Null
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.Rate = 0
$synth.Volume = 95
$format = New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(44100, [System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen, [System.Speech.AudioFormat.AudioChannel]::Mono)
$file = Join-Path $out 'voiceover.wav'
$synth.SetOutputToWaveFile($file, $format)
function Say($voice, $text) { $synth.SelectVoice($voice); $synth.Speak($text) }
Say 'Microsoft Zira Desktop' 'This synthetic MCP demo compares a safe baseline with a risky change.'
Say 'Microsoft Huihui Desktop' '这个合成 MCP 示例，对比基线配置与风险变更。'
Say 'Microsoft Zira Desktop' 'The change adds network access, credentials, sensitive paths, and script execution.'
Say 'Microsoft Huihui Desktop' '变更新增网络访问、凭据、敏感路径，以及脚本执行能力。'
Say 'Microsoft Zira Desktop' 'CapFence reports evidence, source locations, and policy violations.'
Say 'Microsoft Huihui Desktop' 'CapFence 报告证据、源码位置，以及策略违规。'
Say 'Microsoft Zira Desktop' 'Review before merge. Static findings are not proof of a vulnerability.'
Say 'Microsoft Huihui Desktop' '合并前先审查。静态发现，并不等于已经证实的漏洞。'
$synth.SetOutputToNull()
$synth.Dispose()
Write-Output $file

$env:ENCRYPTION_KEY = "test-secret-key"
$env:PORT = "5055"
$dll = "E:\CodeSpace\clash-converter-csharp\bin\Release\net8.0\clash-converter.dll"
$proc = Start-Process -FilePath "dotnet" -ArgumentList $dll -PassThru `
    -RedirectStandardOutput "E:\CodeSpace\clash-converter-csharp\out.log" `
    -RedirectStandardError "E:\CodeSpace\clash-converter-csharp\err.log"
Start-Sleep -Seconds 6

$base = "http://127.0.0.1:5055"

function Post($path, $body) {
    return Invoke-RestMethod -Uri ($base + $path) -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Compress)
}

Write-Host "========== 1. VLESS convert =========="
$r1 = Post "/api/convert" @{ url = "vless://892c6822-3526-46ae-9eca-19ea1b3913f3@example.com:443?type=ws&security=tls&path=%2Fray#Test" }
Write-Host $r1.yaml
Write-Host ("sub_url = " + $r1.sub_url)

Write-Host "========== 2. VLESS sub fetch =========="
$sub = Invoke-RestMethod -Uri $r1.sub_url -Method Get
Write-Host $sub

Write-Host "========== 3. VMess convert =========="
$vmessJson = '{"v":"2","ps":"vm","add":"h.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","type":"none","tls":"tls"}'
$vmess = "vmess://" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($vmessJson))
$r2 = Post "/api/convert" @{ url = $vmess }
Write-Host $r2.yaml

Write-Host "========== 4. Trojan convert =========="
$r3 = Post "/api/convert" @{ url = "trojan://pass123@t.example.com:443?security=tls#t1" }
Write-Host $r3.yaml

Write-Host "========== 5. Clash YAML -> URLs =========="
$yaml = @'
proxies:
  - name: pp
    type: vless
    server: x.com
    port: 443
    uuid: 892c6822-3526-46ae-9eca-19ea1b3913f3
    network: ws
    tls: true
    udp: true
'@
$r4 = Post "/api/to-url" @{ yaml = $yaml }
$r4.proxies | ForEach-Object { Write-Host ($_.type + " => " + $_.url) }

$proc.Kill()
Write-Host "DONE"

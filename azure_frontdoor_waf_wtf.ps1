$outputFile = "waf_remoteaddr_audit.txt"
$summary = @()
$allFindings = @()
Write-Host "-------------------------------------------------------------`n"
Write-Host "`t`t   Azure Front Door WAF WTF?`n`t`tnyxgeek - @trustedSec - 2025.06`n"
Write-Host "-------------------------------------------------------------"

# adding in the front-door extension
Write-Host -NoNewline "`nPlease stand by... adding front-door extension"
az extension add --name front-door *>$null
Write-Host " ... Done`n"

Write-Host "`n[*] Scanning for Front Door WAF Policies that use RemoteAddr...`n"

# Get all subscription IDs
$subscriptions = az account list --query "[].id" -o tsv

foreach ($sub in $subscriptions) {
    Write-Host "`n--- Switching to subscription: $sub ---" -ForegroundColor Cyan
    az account set --subscription $sub

    az group list --query "[].name" -o tsv | ForEach-Object {
        az network front-door waf-policy list --resource-group $_ --query "[].{name:name, rg:'$_'}" -o tsv
    } | ForEach-Object {
        $p = $_ -split "`t"
        $policyName = $p[0]; $rg = $p[1]
        $rules = az network front-door waf-policy rule list --policy-name $policyName --resource-group $rg -o json | ConvertFrom-Json
        $matches = foreach ($rule in $rules) {
            $matchVars = $rule.matchConditions | ForEach-Object { $_.matchVariable }
            if ($matchVars -contains "RemoteAddr" -and -not ($matchVars -contains "SocketAddr")) {
                foreach ($cond in $rule.matchConditions) {
                    if ($cond.matchVariable -eq "RemoteAddr") {
                        $finding = [PSCustomObject]@{
                            Subscription  = $sub
                            ResourceGroup = $rg
                            WAFName       = $policyName
                            RuleName      = $rule.name
                            Operator      = $cond.operator
                            MatchVariable = $cond.matchVariable
                            MatchValues   = ($cond.matchValue -join ', ')
                        }
                        $allFindings += $finding
                        $finding
                    }
                }
            }
        }
        if ($matches) {
            Write-Host "`n⚠️ VULNERABLE RULES FOUND in policy [$policyName] (RG: $rg, SUB: $sub)" -ForegroundColor Yellow
            $matches | Format-Table -AutoSize
            $summary += [PSCustomObject]@{ Subscription = $sub; ResourceGroup = $rg; WAFName = $policyName; VulnerableRules = $matches.Count }
        } else {
            $summary += [PSCustomObject]@{ Subscription = $sub; ResourceGroup = $rg; WAFName = $policyName; VulnerableRules = 0 }
        }
    }
}

Write-Host "`n=== Summary of WAF RemoteAddr Matches (Excluding SocketAddr Rules) ===" -ForegroundColor Cyan
$summary | Format-Table -AutoSize

# Write to file
"=== RemoteAddr Rule Matches (Filtered) ===" | Out-File $outputFile
$allFindings | Format-Table -AutoSize | Out-String | Out-File -Append $outputFile
"`n=== Summary ===" | Out-File -Append $outputFile
$summary | Format-Table -AutoSize | Out-String | Out-File -Append $outputFile

Write-Host "`nResults saved to: $outputFile" -ForegroundColor Green

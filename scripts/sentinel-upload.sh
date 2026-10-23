#!/usr/bin/env bash
# Upload the Mirage STIX bundle to Microsoft Sentinel's Upload Indicators API, 100 objects per request.
# Needs jq, curl and a logged-in az CLI. Usage: WORKSPACE_ID=<workspace id> scripts/sentinel-upload.sh mirage.json
set -euo pipefail
bundle=${1:?usage: sentinel-upload.sh mirage.json}
api="https://api.ti.sentinel.azure.com/workspaces/${WORKSPACE_ID:?set WORKSPACE_ID}"
api+="/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview"
token=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)
total=$(jq '.objects | length' "$bundle")
for ((i = 0; i < total; i += 100)); do
  jq -c --argjson i "$i" '{sourcesystem: "OffSeq Mirage", stixobjects: .objects[$i:$i + 100]}' "$bundle" |
    curl -fsS -X POST "$api" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
      --data-binary @- > /dev/null
done
echo "uploaded $total objects"

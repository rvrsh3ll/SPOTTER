# LinkedIn False Positive & Override Feature

## Problem
WF13 (Domain Recon) pulls LinkedIn company data via Tavily/SerpAPI. Sometimes it pulls the wrong company profile. Re-running enrichment doesn't help because it just overwrites with the same wrong data.

## Solution
Three-part override system:

### 1. Company Node Override Fields
Added to `flowsint-custom/types/company.py`:
- `linkedin_url_override` — manual correct LinkedIn URL
- `linkedin_url_fp` — boolean flag marking current URL as false positive
- `linkedin_override_note` — operator note explaining the correction
- `linkedin_override_at` — timestamp of override

### 2. Webhook Endpoint
**Workflow 33** (`n8n-workflows/33-linkedin-override.json`) accepts corrections:

```bash
POST /webhook/linkedin-override
{
  "campaign_id": "uuid",
  "company_name": "Target Company",
  "linkedin_url": "https://www.linkedin.com/company/correct-name/",
  "mark_fp": true,
  "note": "Wrong company - this is a different organization"
}
```

### 3. Dashboard UI
Organization card now has two buttons next to LinkedIn data:
- **Mark as FP** — marks current URL as false positive, clears it
- **Edit URL** — prompts for correct LinkedIn URL

Both buttons show visual indicators:
- `[FP]` badge when marked as false positive
- `[OVERRIDE]` badge when manual override is active
- Override note displayed below LinkedIn data

## Quick Fix for ttk.ru Campaign

To correct the LinkedIn profile for ttk.ru (TransTeleCom):

### Option 1: Via Dashboard UI
1. Open the ttk.ru campaign in SPOTTER dashboard
2. Go to Domain Recon > Organization card
3. Click **Edit URL** button next to LinkedIn
4. Enter: `https://www.linkedin.com/company/transtelecom`
5. Add note: "Correct LinkedIn for TransTeleCom (ttk.ru)"
6. Click OK

### Option 2: Via CLI
```bash
python3 scripts/linkedin_override_webhook.py \
  --campaign-id <TTK_RU_CAMPAIGN_ID> \
  --company-name "TransTeleCom" \
  --linkedin-url "https://www.linkedin.com/company/transtelecom" \
  --note "Correct LinkedIn for TransTeleCom (ttk.ru)"
```

### Option 3: Via curl
```bash
curl -X POST http://localhost:5678/webhook/linkedin-override \
  -H "Content-Type: application/json" \
  -d '{
    "campaign_id": "<TTK_RU_CAMPAIGN_ID>",
    "company_name": "TransTeleCom",
    "linkedin_url": "https://www.linkedin.com/company/transtelecom",
    "note": "Correct LinkedIn for TransTeleCom (ttk.ru)"
  }'
```

## How It Works

1. **Override is set** via UI button, CLI script, or direct webhook call
2. **Company node is updated** with `linkedin_url_override`, `linkedin_override_note`, `linkedin_override_at`
3. **Dashboard displays** the override with visual indicators
4. **WF13 re-runs** will respect the override (requires WF13 modification - see TODO below)

## WF13 Integration (COMPLETED)

WF13 has been modified to check for override fields before pulling LinkedIn data:

1. **Before the org source section runs**, WF13 queries the graph for the target Company/Organization node
2. **If `linkedin_url_fp` is true**, WF13 skips LinkedIn pull entirely and clears the fields
3. **If `linkedin_url_override` exists**, WF13 uses it instead of searching via Tavily/SerpAPI
4. **Otherwise**, WF13 proceeds with normal LinkedIn pull

The override check is inserted at line 2266 of WF13, before the `if 'org' in sources_set:` block. Both Tavily and SerpAPI LinkedIn pulls are wrapped in conditions that respect the override.

## Testing

1. Set an override via UI or CLI
2. Verify Company node has the override fields:
   ```bash
   curl http://localhost:5001/api/sketches/<SKETCH_ID>/nodes/<NODE_ID> \
     -H "Authorization: Bearer <TOKEN>"
   ```
3. Check dashboard shows `[OVERRIDE]` badge
4. Re-run domain recon (after WF13 modification) - should use override

## Files Modified

- `flowsint-custom/types/company.py` — added override fields
- `n8n-workflows/33-linkedin-override.json` — new webhook workflow
- `scripts/linkedin_override_webhook.py` — CLI tool for overrides
- `frontend/index.html` — UI buttons and JavaScript handlers

## Deployment

1. Import WF33 into n8n:
   ```bash
   sudo scripts/deploy_workflow.sh n8n-workflows/33-linkedin-override.json
   ```

2. Restart flowsint-api to pick up Company type changes:
   ```bash
   sudo docker restart spotter-flowsint-api
   ```

3. Reload dashboard to get new UI code

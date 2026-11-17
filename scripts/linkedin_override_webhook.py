#!/usr/bin/env python3
"""
LinkedIn Override Webhook — Manual correction endpoint for false positive LinkedIn profiles.

POST /webhook/linkedin-override
Body: {
    "campaign_id": "uuid",
    "company_name": "Target Company",  # or company_id
    "linkedin_url": "https://www.linkedin.com/company/correct-name/",
    "mark_fp": true,  # optional: mark current URL as false positive
    "note": "Wrong company - this is a different organization"
}

Updates the Company/Organization node with:
- linkedin_url_override: the correct URL
- linkedin_url_fp: true if marking as FP
- linkedin_override_note: operator's note
- linkedin_override_at: timestamp

When WF13 re-runs, it checks for these fields and respects the override.
"""

import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

try:
    import requests
except ImportError:
    print("ERROR: requests library required", file=sys.stderr)
    sys.exit(1)


FLOWSINT_URL = os.environ.get('FLOWSINT_API_URL', 'http://flowsint-api:5001').rstrip('/')
FLOWSINT_KEY = os.environ.get('FLOWSINT_API_KEY', '')


def find_company_node(sketch_id, company_name=None, company_id=None):
    """Find the Company/Organization node by name or ID."""
    headers = {'Authorization': f'Bearer {FLOWSINT_KEY}', 'Content-Type': 'application/json'}
    
    if company_id:
        # Direct ID lookup
        try:
            r = requests.get(f'{FLOWSINT_URL}/api/sketches/{sketch_id}/nodes/{company_id}',
                           headers=headers, timeout=10)
            if r.ok:
                return r.json().get('node')
        except Exception as e:
            print(f"ERROR: Failed to fetch node {company_id}: {e}", file=sys.stderr)
            return None
    
    if company_name:
        # Search by name in Company and Organization nodes
        try:
            # Try Company type first
            r = requests.get(f'{FLOWSINT_URL}/api/sketches/{sketch_id}/nodes',
                           headers=headers, timeout=10)
            if r.ok:
                nodes = r.json().get('nodes', [])
                for node in nodes:
                    node_type = node.get('nodeType', '').lower()
                    node_label = node.get('nodeLabel', '')
                    if node_type in ('company', 'organization') and node_label.lower() == company_name.lower():
                        return node
        except Exception as e:
            print(f"ERROR: Failed to search nodes: {e}", file=sys.stderr)
    
    return None


def update_linkedin_override(sketch_id, node_id, linkedin_url, mark_fp=False, note=''):
    """Update the Company node with LinkedIn override fields."""
    headers = {'Authorization': f'Bearer {FLOWSINT_KEY}', 'Content-Type': 'application/json'}
    
    now = datetime.now(timezone.utc).isoformat()
    
    updates = {
        'nodeProperties.linkedin_url_override': linkedin_url,
        'nodeProperties.linkedin_override_at': now,
    }
    
    if mark_fp:
        updates['nodeProperties.linkedin_url_fp'] = True
        # Clear the old wrong URL
        updates['nodeProperties.linkedin_company_url'] = ''
        updates['nodeProperties.linkedin_company_name'] = ''
    
    if note:
        updates['nodeProperties.linkedin_override_note'] = note
    
    try:
        r = requests.put(f'{FLOWSINT_URL}/api/sketches/{sketch_id}/nodes/edit',
                        headers=headers,
                        json={'nodeId': node_id, 'updates': updates},
                        timeout=10)
        if r.ok:
            return True, f"Updated node {node_id} with LinkedIn override"
        else:
            return False, f"Failed to update: HTTP {r.status_code} - {r.text}"
    except Exception as e:
        return False, f"Failed to update: {e}"


def handler(event, context):
    """n8n webhook handler."""
    try:
        body = event.get('body', {})
        if isinstance(body, str):
            body = json.loads(body)
    except Exception:
        return {'statusCode': 400, 'body': json.dumps({'error': 'Invalid JSON body'})}
    
    campaign_id = body.get('campaign_id', '').strip()
    company_name = body.get('company_name', '').strip()
    company_id = body.get('company_id', '').strip()
    linkedin_url = body.get('linkedin_url', '').strip()
    mark_fp = bool(body.get('mark_fp', False))
    note = body.get('note', '').strip()
    
    if not campaign_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'campaign_id required'})}
    
    if not company_name and not company_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'company_name or company_id required'})}
    
    if not linkedin_url and not mark_fp:
        return {'statusCode': 400, 'body': json.dumps({'error': 'linkedin_url required (or set mark_fp=true to clear)'})}
    
    # Resolve sketch_id from campaign_id
    sketch_id = campaign_id  # In SPOTTER, campaign_id == sketch_id
    
    # Find the company node
    node = find_company_node(sketch_id, company_name, company_id)
    if not node:
        return {'statusCode': 404, 'body': json.dumps({'error': f'Company not found: {company_name or company_id}'})}
    
    node_id = node.get('id')
    node_label = node.get('nodeLabel', '')
    
    # Update the node
    success, message = update_linkedin_override(sketch_id, node_id, linkedin_url, mark_fp, note)
    
    if success:
        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'ok',
                'message': message,
                'node_id': node_id,
                'node_label': node_label,
                'linkedin_url_override': linkedin_url,
                'linkedin_url_fp': mark_fp,
                'linkedin_override_note': note
            })
        }
    else:
        return {'statusCode': 500, 'body': json.dumps({'error': message})}


if __name__ == '__main__':
    # CLI test mode
    import argparse
    parser = argparse.ArgumentParser(description='Set LinkedIn override for a company')
    parser.add_argument('--campaign-id', required=True, help='Campaign/sketch ID')
    parser.add_argument('--company-name', help='Company name to find')
    parser.add_argument('--company-id', help='Company node ID (alternative to name)')
    parser.add_argument('--linkedin-url', help='Correct LinkedIn URL')
    parser.add_argument('--mark-fp', action='store_true', help='Mark current URL as false positive')
    parser.add_argument('--note', default='', help='Operator note')
    
    args = parser.parse_args()
    
    event = {'body': {
        'campaign_id': args.campaign_id,
        'company_name': args.company_name,
        'company_id': args.company_id,
        'linkedin_url': args.linkedin_url,
        'mark_fp': args.mark_fp,
        'note': args.note
    }}
    
    result = handler(event, None)
    print(json.dumps(json.loads(result['body']), indent=2))

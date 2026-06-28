#!/usr/bin/env python3
import jwt
import json
import sys
import base64
from datetime import datetime

def decode_jwt(token):
    """Decode JWT without verifying signature."""
    try:
        # Split token
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid JWT format (must have 3 parts)"
        # Decode header and payload (base64url)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
        return {'header': header, 'payload': payload, 'signature': parts[2]}, None
    except Exception as e:
        return None, str(e)

def analyze_jwt(token):
    """Perform security analysis on a JWT."""
    decoded, error = decode_jwt(token)
    if error:
        return {'error': error, 'risk': 'N/A'}

    header = decoded['header']
    payload = decoded['payload']
    findings = []
    risk_score = 0

    # Check algorithm
    alg = header.get('alg', 'none')
    if alg == 'none':
        findings.append({'severity': 'HIGH', 'issue': 'Algorithm set to "none" – token can be forged'})
        risk_score += 30
    elif alg not in ['HS256', 'RS256']:
        findings.append({'severity': 'MEDIUM', 'issue': f'Algorithm "{alg}" is less common; consider HS256 or RS256'})
        risk_score += 10

    # Check expiration
    exp = payload.get('exp')
    if exp:
        exp_time = datetime.fromtimestamp(exp)
        now = datetime.now()
        if exp_time < now:
            findings.append({'severity': 'LOW', 'issue': 'Token has expired'})
        else:
            time_left = exp_time - now
            if time_left.days > 30:
                findings.append({'severity': 'MEDIUM', 'issue': f'Token expires in {time_left.days} days – long expiration'})
                risk_score += 5
    else:
        findings.append({'severity': 'HIGH', 'issue': 'No expiration (exp) claim – token never expires'})
        risk_score += 20

    # Check for sensitive data
    sensitive_keys = ['password', 'secret', 'key', 'token', 'api_key', 'apiKey']
    for key in sensitive_keys:
        if key in payload:
            findings.append({'severity': 'HIGH', 'issue': f'Sensitive data "{key}" found in payload'})
            risk_score += 25

    # Check for issuer and audience
    if 'iss' not in payload:
        findings.append({'severity': 'LOW', 'issue': 'No issuer (iss) claim'})
    if 'aud' not in payload:
        findings.append({'severity': 'LOW', 'issue': 'No audience (aud) claim'})

    # Determine risk level
    if risk_score >= 60:
        risk_level = 'HIGH'
    elif risk_score >= 30:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    return {
        'header': header,
        'payload': payload,
        'signature': decoded['signature'],
        'risk_score': risk_score,
        'risk_level': risk_level,
        'findings': findings
    }

def main():
    print("=" * 60)
    print("  JWT TOKEN ANALYZER")
    print("=" * 60)
    print("Enter a JWT token (or press Enter for a sample weak token):")
    token = input("Token: ").strip()
    if not token:
        # Generate a sample weak token for demonstration
        sample_payload = {'user': 'admin', 'role': 'admin', 'password': 'admin123'}
        token = jwt.encode(sample_payload, 'secret', algorithm='HS256')
        print(f"\n[+] Using sample token:\n{token}\n")

    result = analyze_jwt(token)
    if 'error' in result:
        print(f"[!] Error: {result['error']}")
        return

    print("\n📋 Header:")
    print(json.dumps(result['header'], indent=2))
    print("\n📋 Payload:")
    print(json.dumps(result['payload'], indent=2))
    print(f"\n🔑 Signature (truncated): {result['signature'][:20]}...")

    print(f"\n⚠️ Risk Score: {result['risk_score']}/100")
    print(f"📊 Risk Level: {result['risk_level']}")

    if result['findings']:
        print("\n🚨 Findings:")
        for f in result['findings']:
            print(f"  [{f['severity']}] {f['issue']}")

    # Save report
    import datetime as dt
    output_file = f"jwt_analysis_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n💾 Report saved to: {output_file}")

if __name__ == "__main__":
    main()

from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib
import os
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from urllib.parse import urlparse

app = Flask(__name__)

# Load model
print("Loading model...")
if os.path.exists('phishing_model.pkl'):
    model = joblib.load('phishing_model.pkl')
    print("✅ Model loaded!")
else:
    print("Training model...")
    df = pd.read_csv('test_dataset.csv')
    X = df[['sender_spoofed', 'has_urgency', 'has_links', 'link_suspicious', 'body_length']]
    y = df['label'].apply(lambda x: 1 if x == 'phishing' else 0)
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    model.fit(X, y)
    joblib.dump(model, 'phishing_model.pkl')
    print("✅ Model trained!")

# Load threat database
try:
    threat_db = pd.read_csv('threat_database.csv')
    print(f"✅ Threat DB loaded: {len(threat_db)} entries")
except:
    threat_db = pd.DataFrame({'url': [], 'threat_type': [], 'severity': []})
    print("⚠️ Threat database not found")

# Get metrics
df = pd.read_csv('test_dataset.csv')
X = df[['sender_spoofed', 'has_urgency', 'has_links', 'link_suspicious', 'body_length']]
y = df['label'].apply(lambda x: 1 if x == 'phishing' else 0)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
y_pred = model.predict(X_test)

test_results = {
    'accuracy': round(float(accuracy_score(y_test, y_pred)) * 100, 1),
    'precision': round(float(precision_score(y_test, y_pred)) * 100, 1),
    'recall': round(float(recall_score(y_test, y_pred)) * 100, 1),
    'f1': round(float(f1_score(y_test, y_pred)) * 100, 1),
    'true_positives': int(((y_pred == 1) & (y_test == 1)).sum()),
    'true_negatives': int(((y_pred == 0) & (y_test == 0)).sum()),
    'false_positives': int(((y_pred == 1) & (y_test == 0)).sum()),
    'false_negatives': int(((y_pred == 0) & (y_test == 1)).sum())
}

# REAL LINK CHECKING FUNCTION
def check_link_real(url):
    """Check if link is phishing or safe"""
    
    try:
        domain = urlparse(url).netloc.lower()
        
        # 1. KNOWN PHISHING DOMAINS
        phishing_domains = [
            'paypel.com', 'amaz0n.com', 'paypa1.com', 'goog1e.com',
            'micros0ft.com', 'appl3.com', 'appl-e.com', 'amazon-verify.com',
            'paypal-confirm.com', 'google-account.com'
        ]
        
        if domain in phishing_domains:
            return {
                'status': 'PHISHING',
                'threat': 'KNOWN PHISHING DOMAIN',
                'severity': 'CRITICAL',
                'score': 95
            }
        
        # 2. TYPOSQUATTING (Misspelled domains)
        typo_checks = {
            'paypal': ['paypel', 'paypa1', 'paypa-l', 'paypall'],
            'amazon': ['amaz0n', 'amazone', 'amaz-on', 'amazoon'],
            'google': ['goog1e', 'gogle', 'googl-e', 'gogle'],
            'microsoft': ['micros0ft', 'microsft', 'micro-soft'],
            'apple': ['appl3', 'appel', 'aple', 'app-le']
        }
        
        for brand, typos in typo_checks.items():
            for typo in typos:
                if typo in domain:
                    return {
                        'status': 'PHISHING',
                        'threat': f'Typosquatting - Mimics {brand.upper()}',
                        'severity': 'HIGH',
                        'score': 88
                    }
        
        # 3. IP ADDRESS (instead of domain)
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
            return {
                'status': 'SUSPICIOUS',
                'threat': 'Direct IP address (no domain name)',
                'severity': 'HIGH',
                'score': 80
            }
        
        # 4. SHORTENED URLS
        shorteners = ['bit.ly', 'tinyurl', 'short.link', 'ow.ly', 'goo.gl', 'bitly.com', 't.co', 'is.gd']
        if any(s in domain for s in shorteners):
            return {
                'status': 'SUSPICIOUS',
                'threat': 'URL Shortened (hides actual destination)',
                'severity': 'MEDIUM',
                'score': 65
            }
        
        # 5. PROXY SERVICES
        proxies = ['hides.my', 'anonymouse.org', 'proxy']
        if any(p in domain for p in proxies):
            return {
                'status': 'SUSPICIOUS',
                'threat': 'Proxy/Anonymous service detected',
                'severity': 'MEDIUM',
                'score': 70
            }
        
        # 6. SUSPICIOUS TLDS (Top Level Domains)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.download', '.cricket', '.science']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return {
                'status': 'SUSPICIOUS',
                'threat': 'Suspicious top-level domain (.tk, .ml, etc)',
                'severity': 'MEDIUM',
                'score': 60
            }
        
        # 7. UNICODE/PUNYCODE DOMAINS (Homograph attacks)
        if 'xn--' in domain:
            return {
                'status': 'SUSPICIOUS',
                'threat': 'Unicode domain (homograph attack)',
                'severity': 'HIGH',
                'score': 75
            }
        
        # 8. SUBDOMAIN SPOOFING
        parts = domain.split('.')
        if len(parts) > 3:
            return {
                'status': 'SUSPICIOUS',
                'threat': 'Multiple subdomains (suspicious)',
                'severity': 'MEDIUM',
                'score': 55
            }
        
        # ALL CHECKS PASSED - LEGITIMATE
        return {
            'status': 'LEGITIMATE',
            'threat': 'Domain appears safe',
            'severity': 'LOW',
            'score': 5
        }
    
    except Exception as e:
        return {
            'status': 'ERROR',
            'threat': str(e),
            'severity': 'UNKNOWN',
            'score': 0
        }

# EMAIL FEATURE EXTRACTION
def extract_email_features(email_text, sender_email=""):
    """Extract features from email"""
    text_lower = email_text.lower()
    
    # Urgency detection
    urgency_keywords = [
        'urgent', 'confirm', 'verify', 'action required', 'immediately',
        'update payment', 'click here', 'activate', 'suspicious activity',
        'locked', 'suspended', 'disabled', 'expire', 'expired', 'deadline',
        'act now', 'warning', 'alert', 'confirm identity'
    ]
    has_urgency = 1 if any(keyword in text_lower for keyword in urgency_keywords) else 0
    
    # Link detection
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    links = re.findall(url_pattern, email_text)
    has_links = 1 if len(links) > 0 else 0
    
    # Link suspicion
    link_suspicious = 0
    for link in links:
        result = check_link_real(link)
        if result['score'] > 50:
            link_suspicious = 1
            break
    
    # Sender spoofing
    sender_spoofed = 0
    if sender_email:
        spoofed_patterns = ['paypel', 'amaz0n', 'paypa1', 'microsof', 'appl3', 'goog1e']
        if any(pattern in sender_email.lower() for pattern in spoofed_patterns):
            sender_spoofed = 1
    
    # Body length
    body_length = len(email_text)
    
    return {
        'has_urgency': has_urgency,
        'has_links': has_links,
        'link_suspicious': link_suspicious,
        'sender_spoofed': sender_spoofed,
        'body_length': body_length,
        'links_found': links
    }

@app.route('/')
def index():
    return render_template('dashboard.html', test_results=test_results)

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        
        if 'email_text' in data:
            email_text = data.get('email_text', '')
            sender_email = data.get('sender_email', '')
            
            features_dict = extract_email_features(email_text, sender_email)
            
            features = [[
                features_dict['sender_spoofed'],
                features_dict['has_urgency'],
                features_dict['has_links'],
                features_dict['link_suspicious'],
                features_dict['body_length']
            ]]
        else:
            features = [[
                int(data.get('sender_spoofed', 0)),
                int(data.get('has_urgency', 0)),
                int(data.get('has_links', 0)),
                int(data.get('link_suspicious', 0)),
                int(data.get('body_length', 100))
            ]]
            features_dict = {
                'sender_spoofed': features[0][0],
                'has_urgency': features[0][1],
                'has_links': features[0][2],
                'link_suspicious': features[0][3],
                'body_length': features[0][4],
                'links_found': []
            }
        
        # ML Prediction
        pred = model.predict(features)[0]
        proba = model.predict_proba(features)[0]
        
        risk_score = int(proba[1] * 100)
        confidence = round(float(max(proba)) * 100, 1)
        
        # Explanation
        explanation = []
        
        if features_dict['sender_spoofed']:
            explanation.append("⚠️ Sender domain appears spoofed")
        
        if features_dict['has_urgency']:
            explanation.append("⚠️ Contains urgent/threatening language")
        
        if features_dict['has_links']:
            explanation.append("🔗 Email contains links")
            if features_dict['link_suspicious']:
                explanation.append("⚠️ Some links appear suspicious")
        
        if features_dict['body_length'] < 50:
            explanation.append("⚠️ Very short email (unusual for legitimate)")
        
        if len(explanation) == 0:
            explanation.append("✅ Email appears legitimate")
        
        return jsonify({
            'is_phishing': int(pred),
            'risk_score': risk_score,
            'confidence': confidence,
            'explanation': explanation,
            'features': {
                'urgency': features_dict['has_urgency'],
                'links': features_dict['has_links'],
                'suspicious_links': features_dict['link_suspicious'],
                'spoofed_sender': features_dict['sender_spoofed'],
                'body_length': features_dict['body_length']
            }
        })
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/check-link', methods=['POST'])
def check_link_route():
    """Real link threat checking"""
    try:
        data = request.json
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        if not url.startswith('http'):
            url = 'http://' + url
        
        result = check_link_real(url)
        
        return jsonify({
            'url': url,
            'domain': urlparse(url).netloc,
            'status': result['status'],
            'threat': result['threat'],
            'severity': result['severity'],
            'risk_score': result['score']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    print("=" * 70)
    print("🔍 ADVANCED PHISHING DETECTOR WITH REAL LINK CHECKING")
    print("=" * 70)
    print(f"✅ Model Accuracy: {test_results['accuracy']}%")
    print(f"✅ Real Link Threat Checking: ACTIVE")
    print("✅ Features: Email Analysis + ML + Link Verification")
    print("🌐 Server: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(debug=True, port=5000)
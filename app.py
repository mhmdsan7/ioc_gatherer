from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
import requests
import pandas as pd
import os
from dotenv import load_dotenv
from datetime import datetime
import io

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

class IoCSearcher:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
    def search_abuseipdb(self, keyword):
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if not api_key:
            return []
            
        base_url = "https://api.abuseipdb.com/api/v2/check"
        results = []
        
        try:
            params = {
                'ipAddress': keyword,
                'maxAgeInDays': '90'
            }
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            
            response = requests.get(base_url, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['data']:
                    results.append({
                        'type': 'IP',
                        'value': keyword,
                        'source': 'AbuseIPDB',
                        'confidence': data['data']['abuseConfidenceScore'],
                        'country': data['data']['countryCode'],
                        'last_reported': data['data']['lastReportedAt']
                    })
        except Exception as e:
            print(f"Error searching AbuseIPDB: {str(e)}")
            
        return results
        
    def search_virustotal(self, keyword):
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            return []
            
        base_url = "https://www.virustotal.com/api/v3"
        results = []
        
        try:
            if '.' in keyword:  # Could be IP or domain
                endpoint = f"{base_url}/ip_addresses/{keyword}"
            else:  # Assume it's a hash
                endpoint = f"{base_url}/files/{keyword}"
                
            headers = {
                'x-apikey': api_key
            }
            
            response = requests.get(endpoint, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    results.append({
                        'type': 'IP/Domain/Hash',
                        'value': keyword,
                        'source': 'VirusTotal',
                        'malicious': data['data']['attributes'].get('last_analysis_stats', {}).get('malicious', 0),
                        'last_analysis': data['data']['attributes'].get('last_analysis_date', '')
                    })
        except Exception as e:
            print(f"Error searching VirusTotal: {str(e)}")
            
        return results
        
    def search_threatfox(self, keyword):
        api_key = os.getenv('THREATFOX_API_KEY')
        if not api_key:
            return []
            
        base_url = "https://threatfox.abuse.ch/api/v1/"
        results = []
        
        try:
            payload = {
                'query': 'search_ioc',
                'search_term': keyword
            }
            headers = {
                'API-KEY': api_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(base_url, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    for ioc in data['data']:
                        results.append({
                            'type': ioc.get('ioc_type', 'Unknown'),
                            'value': ioc.get('ioc', keyword),
                            'source': 'ThreatFox',
                            'malware': ioc.get('malware', 'Unknown'),
                            'first_seen': ioc.get('first_seen', '')
                        })
        except Exception as e:
            print(f"Error searching ThreatFox: {str(e)}")
            
        return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/search', methods=['POST'])
def search_iocs():
    data = request.json
    keywords = [k.strip() for k in data.get('keywords', '').split(',')]
    
    searcher = IoCSearcher()
    results = []
    
    for keyword in keywords:
        results.extend(searcher.search_abuseipdb(keyword))
        results.extend(searcher.search_virustotal(keyword))
        results.extend(searcher.search_threatfox(keyword))
    
    return jsonify(results)

@app.route('/api/export', methods=['POST'])
def export_to_excel():
    data = request.json
    results = data.get('results', [])
    
    if not results:
        return jsonify({'error': 'No data to export'}), 400
        
    df = pd.DataFrame(results)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'ioc_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    )

if __name__ == '__main__':
    app.run(debug=True) 
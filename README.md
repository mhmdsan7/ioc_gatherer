# IoC Gatherer Web Application

A web-based tool for gathering Indicators of Compromise (IoCs) from various threat intelligence sources.

## Features

- Modern web interface
- Multi-source IoC gathering (AbuseIPDB, VirusTotal, ThreatFox)
- Real-time results display
- Export to Excel functionality
- Responsive design

## Setup

1. Install Python 3.8 or higher
2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your API keys:
```
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
THREATFOX_API_KEY=your_threatfox_api_key_here
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your web browser and go to:
```
http://localhost:5000
```

3. Enter IoCs (comma-separated) in the search box
4. Click "Search IoCs" to start the search
5. View results in real-time
6. Export results to Excel if needed

## API Keys

You'll need API keys from:
- AbuseIPDB: https://www.abuseipdb.com/account/api
- VirusTotal: https://www.virustotal.com/gui/join-us
- ThreatFox: https://threatfox.abuse.ch/api/

## Project Structure

```
ioc_gatherer/
├── app.py              # Flask application
├── requirements.txt    # Python dependencies
├── .env               # API keys (create this file)
├── README.md          # This file
└── templates/
    └── index.html     # Web interface
``` 
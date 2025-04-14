# IoC Gatherer - Threat Intelligence Tool

A web-based tool for gathering and analyzing Indicators of Compromise (IoCs) from multiple sources, designed to assist in creating weekly threat intelligence bulletins.

## Features

- **Multi-Feed Support**: Create multiple feeds for different threat categories or campaigns
- **Comprehensive IoC Analysis**: Supports various IoC types:
  - IP Addresses (via AbuseIPDB and VirusTotal)
  - Domain Names (via VirusTotal)
  - File Hashes (MD5, SHA1, SHA256 via VirusTotal)
  - CVEs (via NIST NVD)
- **Multiple Intelligence Sources**:
  - AbuseIPDB
  - VirusTotal
  - ThreatFox
  - NIST NVD
- **Excel Export**: Generate professional reports with:
  - Separate sheets for each feed
  - Formatted titles (size 18)
  - Auto-adjusted column widths
  - Comprehensive IoC details

## Setup

1. Clone the repository:
```bash
git clone <https://github.com/mhmdsan7/ioc_gatherer.git>
cd ioc_gatherer
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with your API keys:
```
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
THREATFOX_API_KEY=your_threatfox_key
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Access the web interface at `http://localhost:5000`

3. For each threat feed:
   - Click "Add Feed"
   - Enter a feed title
   - Input IoCs (comma-separated):
     - IP addresses
     - Domain names
     - File hashes (MD5, SHA1, SHA256)
     - CVE IDs (format: CVE-YYYY-XXXXX)

4. Click "Search All" to gather intelligence

5. Review the results for each feed

6. Click "Export to Excel" to generate a formatted report

## API Endpoints

### POST /api/search
Search for IoCs across multiple feeds.

Request body:
```json
{
    "feeds": [
        {
            "title": "Feed Title",
            "iocs": "8.8.8.8, example.com, 5f4dcc3b5aa765d61d8327deb882cf99, CVE-2023-12345"
        }
    ]
}
```

### POST /api/export
Export results to Excel.

Request body:
```json
{
    "results": {
        "Feed Title": [
            {
                "type": "IP",
                "value": "8.8.8.8",
                "source": "AbuseIPDB",
                ...
            }
        ]
    }
}
```

## Dependencies

- Flask
- Flask-CORS
- requests
- pandas
- python-dotenv
- openpyxl

## Contributing
Thank you for being interested in my project. 
If u have any questions or improvement feel free to contribute
my [LinkedIn](https://www.linkedin.com/in/aladghm/) if u want to get in touch.

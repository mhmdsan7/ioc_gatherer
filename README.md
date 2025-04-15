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
  - Formatted titles
  - Auto-adjusted column widths
  - Comprehensive IoC details

## Setup

### Option 1: Local Setup

1. Clone the repository:
```bash
git clone <your-repository-url>
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

### Option 2: Docker Setup

1. Clone the repository:
```bash
git clone <your-repository-url>
cd ioc_gatherer
```

2. Create a `.env` file with your API keys (as shown above)

3. Choose one of these methods to run the application:

   **Method A: Using Docker Compose (Recommended)**
   ```bash
   # Start the application
   docker-compose up -d

   # View logs
   docker-compose logs -f

   # Stop the application
   docker-compose down
   ```

   **Method B: Using Docker directly**
   ```bash
   # Build the image
   docker build -t ioc-gatherer .

   # Run the container
   docker run -p 5000:5000 --env-file .env ioc-gatherer
   ```

## Usage

1. Access the web interface:
   - Local setup: `http://localhost:5000`
   - Docker setup: `http://localhost:5000`

2. For each threat feed:
   - Click "Add Feed"
   - Enter a feed title
   - Input IoCs (comma-separated):
     - IP addresses
     - Domain names
     - File hashes (MD5, SHA1, SHA256)
     - CVE IDs (format: CVE-YYYY-XXXXX)

3. Click "Search All" to gather intelligence

4. Review the results for each feed

5. Click "Export to Excel" to generate a formatted report

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

## Docker Support
The application can be containerized using Docker. The provided Docker configuration includes:

### Dockerfile:
- Uses Python 3.9 slim image for minimal size
- Installs necessary system and Python dependencies
- Sets up the application in a production-ready environment
- Exposes port 5000 for web access

### docker-compose.yaml:
- Simplifies deployment and configuration
- Manages environment variables via .env file
- Provides persistent storage for exported files
- Includes health checks and automatic restart
- Makes it easier to manage the application lifecycle

To use docker-compose:
```bash
# Start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```
To rebuild the container after changes:
```bash
docker-compose up -d --build
```
## Contributing
Thank you for being interested in my project. 
If u have any questions or improvement feel free to contribute
my [LinkedIn](https://www.linkedin.com/in/aladghm/) if u want to get in touch.

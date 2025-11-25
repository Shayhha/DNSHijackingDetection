# DNS Hijacking Detection

DNS Hijacking Detection is a security tool designed to identify and analyze suspicious DNS traffic that may indicate hijacking or data exfiltration attempts. It leverages packet sniffing, DNS TXT record inspection, and VirusTotal integration to detect malicious domains and encoded payloads. The system also includes a DNS traffic simulator for testing and research purposes.

## Features

- **Real-Time DNS Sniffing:** Captures and analyzes DNS TXT response packets using Scapy.
- **Suspicious Payload Detection:** Identifies suspicious commands and Base64-encoded data hidden in DNS responses.
- **VirusTotal Integration:** Fetches domain reputation reports via the VirusTotal API for flagged domains.
- **Traffic Simulation:** Generate custom or random DNS TXT response packets to simulate hijacking attacks.
- **Detailed Reporting:** Provides packet details, decoded payloads, and domain reputation analysis.
- **Console Interface:** Simple interactive menu for scanning, simulating, and analyzing DNS traffic.

## Clone Repository

To get started, clone the repository:

```shell
git clone https://github.com/Shayhha/DNSHijackingDetection
```

## API .env Configuration:

Navigate to the config folder, create a new .env file and insert the following:

```shell
VIRUS_TOTAL_API_KEY="your_virus_total_api_key"
```

## Usage

1. **Run the Application:**
   ```shell
   python DNSHijackingDetection.py
   ```
2. **Select Operation:**
   
   
   [1] Scan for DNS hijacking attacks<br>
   [2] Send custom DNS TXT response packets<br>
   [3] Send random suspicious DNS TXT response packets<br>
   [4] Exit<br>
   
4. **View Results:**
   - Suspicious packets are displayed with detailed information.
   - VirusTotal reports are fetched and analyzed.

## Requirements

Ensure you have the following dependencies installed:

- Python 3.13
- Scapy
- requests
- python-dotenv

Install dependencies using pip:

```shell
pip install scapy
pip install requests
pip install python-dotenv
```

## Contact

For questions or feedback, please contact [shayhha@gmail.com](mailto:shayhha@gmail.com).

## License

This tool is released under the [MIT License](LICENSE.txt).

© All rights reserved to Shayhha (Shay Hahiashvili).

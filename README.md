#  The Ghost-Sniffer

**Wireless Security Auditing Tool**

A comprehensive four-phase wireless network security auditing tool that combines passive network discovery, vulnerability analysis, exploit testing, and detailed reporting.

## LEGAL WARNING

**THIS TOOL IS FOR AUTHORIZED SECURITY USE ONLY**

- Only use on networks you own or have explicit written authorization to test
- Unauthorized access to computer networks is illegal in most jurisdictions
- You are solely responsible for your actions
- The authors and contributors are not responsible for misuse of this tool

## Features

### Phase 1: The Third Ear (Network Discovery)
- Passive wireless network scanning
- Real-time network discovery using Scapy
- Support for Windows (via netsh) and Linux
- Manual network entry and Windows network import
- Interface detection and selection

### Phase 2: The Covenant-Pulse (Vulnerability Analysis)
- Automated vulnerability detection
- CVSS scoring for identified vulnerabilities
- Encryption type analysis (Open, WEP, WPA, WPA2, WPA3)
- Risk scoring and security recommendations
- Detection of weak SSID patterns and default credentials

### Phase 3: The Legion of Keys (Exploit Testing)
- **Simulation Mode**: Safe demonstration of exploit techniques
- **Real Exploit Mode**: Actual attack testing (requires authorization)
  - WEP cracking (aircrack-ng)
  - WPS PIN brute-force (reaver)
  - Dictionary attacks (hashcat/aircrack-ng)
  - Handshake capture
- Progress tracking and detailed exploit results

### Phase 4: The Scroll of Truths (Reporting)
- Comprehensive security audit reports
- Risk heat maps and prioritized target lists
- Export formats: JSON, HTML, CSV, PDF
- Session save/load functionality
- Executive summaries and detailed vulnerability breakdowns

## Requirements

### Python Dependencies
- Python 3.7 or higher
- scapy >= 2.5.0 (required)
- reportlab >= 3.6.0 (for PDF export)
- netifaces >= 0.11.0 (optional, for enhanced interface detection)

### System Requirements

#### Windows
- Npcap (https://npcap.com/) - Install with "WinPcap API-compatible Mode" enabled
- Administrator privileges for packet capture
- Optional: aircrack-ng suite for real exploits

#### Linux
- Root/sudo access for packet capture
- Wireless adapter with monitor mode support
- Optional: aircrack-ng, reaver, hashcat, hcxdumptool for real exploits

## Installation

1. **Clone or download this repository**

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Or install in editable mode:
   ```bash
   pip install -e .
   ```

3. **Install Npcap (Windows only):**
   - Download from https://npcap.com/
   - Install with "WinPcap API-compatible Mode" checked
   - Restart your computer after installation

4. **Install exploit tools (optional, for real exploit mode):**
   - **Linux:**
     ```bash
     sudo apt-get install aircrack-ng reaver hashcat hcxdumptool hcxtools
     ```
   - **Windows:**
     - Download aircrack-ng from https://www.aircrack-ng.org/
     - Download hashcat from https://hashcat.net/
     - Add tools to your system PATH

## Usage

### Quick Start

**Windows:**
```batch
run_ghost_sniffer.bat
```

**Linux/Mac:**
```bash
python ghost_sniffer.py
```

**PowerShell:**
```powershell
.\run_ghost_sniffer.ps1
```

### Basic Workflow

1. **Phase 1 - Network Discovery:**
   - Select your wireless interface
   - Click "Open the Third Ear" to start scanning
   - Networks will appear in real-time
   - Alternative: Use "Import from Windows Scanner" or "Add Network Manually"

2. **Phase 2 - Vulnerability Analysis:**
   - Click "Invoke Protocol-Daemon" after Phase 1
   - Review vulnerability analysis and risk scores

3. **Phase 3 - Exploit Testing:**
   - Click "Deploy Autopwn-Sprite"
   - Choose simulation mode (safe) or real exploit mode (requires authorization)
   - Monitor exploit progress

4. **Phase 4 - Reporting:**
   - Click "Render Vulnerability Cartograph"
   - Review the comprehensive report
   - Export in your preferred format (JSON, HTML, CSV, PDF)

### Session Management

- **Save Session**: Save all captured data, analyses, and reports to a JSON file
- **Load Session**: Restore a previous session from a saved JSON file

## Logging

- Application logs are written to:
  - Windows: `%LOCALAPPDATA%\GhostSniffer\logs\ghost_sniffer.log`
  - Linux/Mac: `~/.ghost_sniffer/logs/ghost_sniffer.log`
- Use this file for troubleshooting and incident reviews

## Testing

Run the unit tests:
```bash
python -m unittest discover -s tests
```

## Windows Build (Executable)

Install build tools and create a standalone EXE:
```powershell
.\scripts\build_windows.ps1
```

Or with CMD:
```batch
scripts\build_windows.bat
```

The executable will be written to `dist\Ghost-Sniffer-<version>.exe`.

## Project Structure

```
.
├── ghost_sniffer.py          # Main application and GUI
├── real_exploits.py          # Real exploit engine implementation
├── requirements.txt          # Python dependencies
├── run_ghost_sniffer.bat     # Windows batch launcher
├── run_ghost_sniffer.ps1     # PowerShell launcher
├── test_interface.py         # Interface testing utility
└── README.md                 # This file
```

## Troubleshooting

### "Npcap is not installed" (Windows)
- Install Npcap from https://npcap.com/
- Ensure "WinPcap API-compatible Mode" is enabled during installation
- Restart your computer

### "Permission denied" / "Access denied"
- Run as Administrator (Windows) or with sudo (Linux)
- Ensure your wireless adapter supports monitor mode

### "No interfaces found"
- Check that your wireless adapter is enabled
- On Linux, ensure the adapter is not in use by NetworkManager
- Try running with elevated privileges

### "No beacon frames captured"
- Ensure wireless networks are in range
- On Windows, some adapters don't support monitor mode - use "Import from Windows Scanner" instead
- On Linux, set the interface to monitor mode: `sudo iwconfig <interface> mode monitor`

### PDF export fails
- Ensure reportlab is installed: `pip install reportlab`
- Check that you have write permissions to the export location

## Security Notes

- This tool performs real security testing when real exploit tools are available
- Always obtain proper authorization before testing
- Use simulation mode for demonstrations and learning
- Real exploit mode should only be used on networks you own or have explicit permission to test

## Contributing

This is a demonstration/educational tool. Contributions should focus on:
- Bug fixes
- Documentation improvements
- Code quality enhancements
- Educational value

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool.

## Acknowledgments

- Built with Scapy for packet manipulation
- Uses aircrack-ng, reaver, and hashcat for real exploit capabilities
- Inspired by the need for comprehensive wireless security auditing tools

## Version

Current Version: 1.0.0

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**

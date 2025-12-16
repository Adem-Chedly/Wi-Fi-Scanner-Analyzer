# 📡 Wi-Fi Scanner & Analyzer

A professional-grade Wi-Fi network scanner with a graphical user interface that displays real-time information about nearby wireless networks.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## 🌟 Features

- **Real-Time Scanning**: Scan actual Wi-Fi networks in your environment
- **Cross-Platform Support**: Works on Windows, Linux, and macOS
- **Graphical Interface**: Modern, user-friendly GUI built with Tkinter
- **Network Details**: View SSID, BSSID, signal strength, channel, and security type
- **Signal Quality Analysis**: Automatic quality rating (Excellent/Good/Fair/Weak)
- **Channel Congestion**: Visual analysis of channel usage and interference
- **Auto-Refresh**: Optional automatic scanning every 10 seconds
- **Statistics Dashboard**: Real-time stats on total, secure, and open networks
- **Sorting**: Networks automatically sorted by signal strength

## 📋 Requirements

### All Platforms
- Python 3.7 or higher
- Tkinter (usually comes with Python)

### Platform-Specific Requirements

#### Windows
- No additional requirements
- Uses built-in `netsh` command

#### Linux
- NetworkManager with `nmcli` (usually pre-installed)
- Install if missing:
  ```bash
  sudo apt-get install network-manager  # Ubuntu/Debian
  sudo dnf install NetworkManager        # Fedora
  sudo pacman -S networkmanager          # Arch
  ```

#### macOS
- Uses built-in `airport` utility
- No additional installation required

## 🚀 Installation

1. **Clone or download the repository**
   ```bash
   git clone https://github.com/yourusername/wifi-scanner.git
   cd wifi-scanner
   ```

2. **Ensure Python 3.7+ is installed**
   ```bash
   python --version
   # or
   python3 --version
   ```

3. **Run the application**
   ```bash
   python wifi_scanner_gui.py
   # or
   python3 wifi_scanner_gui.py
   ```

## 💻 Usage

### Basic Usage

1. **Launch the application**
   ```bash
   python wifi_scanner_gui.py
   ```

2. **Click "🔍 Scan Networks"** to start scanning

3. **View results** in the Networks tab with:
   - Network Name (SSID)
   - MAC Address (BSSID)
   - Signal Strength with quality rating
   - Channel number
   - Security type

4. **Check Channel Analysis** tab for:
   - Visual congestion analysis
   - Most congested channels
   - Recommended channels

### Advanced Features

- **Auto-Refresh**: Enable "Auto-refresh (10s)" checkbox for continuous monitoring
- **Multiple Tabs**: Switch between Networks, Channel Analysis, and System Info
- **Statistics**: View real-time counts of total, secure, and open networks

## 📊 Understanding the Data

### Signal Strength
- **Excellent (>70%)**: Strong signal, optimal for use
- **Good (50-70%)**: Reliable connection
- **Fair (30-50%)**: Usable but may have issues
- **Weak (<30%)**: Poor connection quality

### Security Types
- **WPA3**: Most secure (latest standard)
- **WPA2**: Secure (widely used)
- **WPA**: Older security (less secure)
- **WEP**: Outdated (not recommended)
- **Open**: No security (avoid for sensitive data)

### Channel Information
- **2.4GHz Band**: Channels 1-14 (most common)
  - Non-overlapping channels: 1, 6, 11
  - Longer range, more interference
- **5GHz Band**: Channels 36-165
  - Less interference, shorter range
  - Higher speeds available

## 🔧 Troubleshooting

### Linux: "nmcli not found"
```bash
# Install NetworkManager
sudo apt-get install network-manager
```

### Linux: Permission Issues
Some Linux distributions may require elevated privileges:
```bash
sudo python3 wifi_scanner_gui.py
```

### Windows: No Networks Found
- Ensure Wi-Fi adapter is enabled
- Check that wireless service is running
- Try running as Administrator

### macOS: Command Not Found
The airport utility should be available by default. If not:
```bash
# Verify the path exists
ls /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
```

## 🛠️ Technical Details

### System Commands Used

| Platform | Command |
|----------|---------|
| Windows | `netsh wlan show networks mode=bssid` |
| Linux | `nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi` |
| macOS | `airport -s` |

### Architecture
```
wifi_scanner_gui.py
├── WiFiScanner (Backend)
│   ├── scan_networks()
│   ├── _scan_windows()
│   ├── _scan_linux()
│   └── _scan_macos()
└── WiFiScannerGUI (Frontend)
    ├── setup_ui()
    ├── start_scan()
    ├── update_ui()
    └── update_channel_analysis()
```

## 📝 Code Structure

```python
# Main components:

1. WiFiScanner class
   - Cross-platform network scanning
   - Platform-specific implementations
   - Data parsing and normalization

2. WiFiScannerGUI class
   - Tkinter-based user interface
   - Real-time data visualization
   - Threading for non-blocking scans
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see below:

```
MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🐛 Known Issues

- Linux: May require sudo for full network information
- Large number of networks (50+) may slow down UI updates
- Some older Wi-Fi adapters may not report all information

## 🔮 Future Enhancements

- [ ] Export results to CSV/JSON
- [ ] Network strength graphs over time
- [ ] Connect to network directly from GUI
- [ ] Save favorite networks
- [ ] Network speed testing
- [ ] GPS location tagging
- [ ] Historical data tracking
- [ ] Dark mode theme

## 📧 Contact & Support

- **Issues**: Please report bugs on the GitHub Issues page
- **Questions**: Open a discussion on GitHub Discussions
- **Email**: your.email@example.com

## 🙏 Acknowledgments

- Built with Python and Tkinter
- Uses native system commands for network scanning
- Inspired by professional network analysis tools

---

**Made with ❤️ for network enthusiasts and professionals**

⭐ Star this repository if you find it useful!
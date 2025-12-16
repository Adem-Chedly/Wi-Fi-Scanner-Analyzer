#!/usr/bin/env python3
"""
Wi-Fi Scanner & Analyzer - GUI Application
Real-time Wi-Fi network scanner with graphical interface
"""

import subprocess
import re
import platform
import threading
import time
from datetime import datetime
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

class WiFiScanner:
    def __init__(self):
        self.system = platform.system()
        self.debug = True
        
    def scan_networks(self):
        """Scan for Wi-Fi networks based on the operating system"""
        if self.system == "Windows":
            return self._scan_windows()
        elif self.system == "Linux":
            return self._scan_linux()
        elif self.system == "Darwin":
            return self._scan_macos()
        else:
            return []
    
    def _scan_windows(self):
        """Scan Wi-Fi networks on Windows using netsh"""
        try:
            # Run netsh command
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=15
            )
            
            if self.debug:
                print("=== RAW OUTPUT ===")
                print(result.stdout)
                print("=== END RAW OUTPUT ===")
            
            networks = []
            current_network = {}
            lines = result.stdout.split('\n')
            
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                
                # Look for SSID line
                if line.startswith('SSID'):
                    # Save previous network if it exists
                    if current_network and 'ssid' in current_network:
                        if 'bssid' in current_network:  # Only add if we have BSSID
                            networks.append(current_network.copy())
                    
                    # Extract SSID
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        ssid = parts[1].strip()
                        if ssid and ssid != '':
                            current_network = {'ssid': ssid}
                        else:
                            current_network = {'ssid': 'Hidden Network'}
                
                elif 'Network type' in line and current_network:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_network['type'] = parts[1].strip()
                
                elif 'Authentication' in line and current_network:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        current_network['security'] = parts[1].strip()
                
                elif line.startswith('BSSID') and current_network:
                    # Extract BSSID
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        bssid = parts[1].strip()
                        current_network['bssid'] = bssid
                        
                        # Now look ahead for Signal and Channel
                        j = i + 1
                        while j < len(lines) and j < i + 5:
                            next_line = lines[j].strip()
                            
                            if 'Signal' in next_line:
                                signal_match = re.search(r'(\d+)%', next_line)
                                if signal_match:
                                    current_network['signal'] = int(signal_match.group(1))
                            
                            if 'Channel' in next_line:
                                channel_match = re.search(r'(\d+)', next_line)
                                if channel_match:
                                    current_network['channel'] = int(channel_match.group(1))
                                # After finding channel, save this BSSID entry
                                if 'signal' in current_network:
                                    networks.append(current_network.copy())
                                    current_network = {'ssid': current_network['ssid']}
                                    if 'security' in networks[-1]:
                                        current_network['security'] = networks[-1]['security']
                                break
                            
                            j += 1
                
                i += 1
            
            # Add the last network if it exists
            if current_network and 'ssid' in current_network and 'bssid' in current_network:
                networks.append(current_network)
            
            if self.debug:
                print(f"\n=== PARSED {len(networks)} NETWORKS ===")
                for net in networks:
                    print(net)
            
            return networks
            
        except subprocess.TimeoutExpired:
            print("Error: Command timed out")
            return []
        except Exception as e:
            print(f"Error scanning on Windows: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _scan_linux(self):
        """Scan Wi-Fi networks on Linux using nmcli"""
        networks = []
        
        try:
            # First, try to rescan
            subprocess.run(['nmcli', 'dev', 'wifi', 'rescan'], 
                         capture_output=True, timeout=5)
            time.sleep(1)
            
            # Now get the list
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'dev', 'wifi', 'list'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if self.debug:
                print("=== RAW OUTPUT ===")
                print(result.stdout)
                print("=== END RAW OUTPUT ===")
            
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 5:
                        ssid = parts[0] if parts[0] and parts[0] != '--' else 'Hidden Network'
                        bssid = parts[1] if parts[1] else 'N/A'
                        channel = parts[2] if parts[2] else 'N/A'
                        signal = parts[3] if parts[3] else '0'
                        security = ':'.join(parts[4:]) if len(parts) > 4 else 'Open'
                        
                        try:
                            signal_int = int(signal)
                        except:
                            signal_int = 0
                        
                        networks.append({
                            'ssid': ssid,
                            'bssid': bssid,
                            'channel': channel,
                            'signal': signal_int,
                            'security': security if security else 'Open'
                        })
            
            if self.debug:
                print(f"\n=== PARSED {len(networks)} NETWORKS ===")
                for net in networks:
                    print(net)
            
            return networks
            
        except FileNotFoundError:
            error_net = {
                'ssid': 'ERROR: nmcli not found',
                'bssid': 'Install network-manager',
                'channel': 'N/A',
                'signal': 0,
                'security': 'N/A'
            }
            return [error_net]
        except Exception as e:
            print(f"Error scanning on Linux: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _scan_macos(self):
        """Scan Wi-Fi networks on macOS using airport"""
        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if self.debug:
                print("=== RAW OUTPUT ===")
                print(result.stdout)
                print("=== END RAW OUTPUT ===")
            
            networks = []
            lines = result.stdout.split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 7:
                        networks.append({
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'signal': int(parts[2]),
                            'channel': parts[3].split(',')[0],
                            'security': ' '.join(parts[6:])
                        })
            
            if self.debug:
                print(f"\n=== PARSED {len(networks)} NETWORKS ===")
                for net in networks:
                    print(net)
            
            return networks
            
        except Exception as e:
            print(f"Error scanning on macOS: {e}")
            import traceback
            traceback.print_exc()
            return []

class WiFiScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Fi Scanner & Analyzer")
        self.root.geometry("1200x700")
        self.scanner = WiFiScanner()
        self.scanning = False
        self.networks = []
        
        self.setup_ui()
        
        # Show initial message
        self.status_label.config(text=f"Ready to scan | OS: {self.scanner.system}")
        
    def setup_ui(self):
        """Setup the user interface"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Title Frame
        title_frame = tk.Frame(self.root, bg="#2563eb", height=80)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame, 
            text="📡 Wi-Fi Scanner & Analyzer",
            font=("Arial", 24, "bold"),
            bg="#2563eb",
            fg="white"
        )
        title_label.pack(pady=20)
        
        # Control Frame
        control_frame = tk.Frame(self.root, bg="#f3f4f6", height=60)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_button = tk.Button(
            control_frame,
            text="🔍 Scan Networks",
            command=self.start_scan,
            bg="#2563eb",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.auto_scan_var = tk.BooleanVar()
        auto_scan_check = tk.Checkbutton(
            control_frame,
            text="Auto-refresh (10s)",
            variable=self.auto_scan_var,
            command=self.toggle_auto_scan,
            font=("Arial", 10),
            bg="#f3f4f6"
        )
        auto_scan_check.pack(side=tk.LEFT, padx=20)
        
        self.status_label = tk.Label(
            control_frame,
            text="Ready to scan",
            font=("Arial", 10),
            bg="#f3f4f6",
            fg="#6b7280"
        )
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Debug button
        debug_button = tk.Button(
            control_frame,
            text="🐛 Debug",
            command=self.show_debug,
            bg="#6b7280",
            fg="white",
            font=("Arial", 10),
            padx=10,
            pady=8
        )
        debug_button.pack(side=tk.RIGHT, padx=5)
        
        # Stats Frame
        stats_frame = tk.Frame(self.root, bg="white")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.total_networks_label = self.create_stat_card(stats_frame, "Total Networks", "0", "#3b82f6")
        self.secure_networks_label = self.create_stat_card(stats_frame, "Secure", "0", "#10b981")
        self.open_networks_label = self.create_stat_card(stats_frame, "Open", "0", "#ef4444")
        self.channels_label = self.create_stat_card(stats_frame, "Active Channels", "0", "#8b5cf6")
        
        # Main content with notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Networks Tab
        networks_frame = tk.Frame(notebook, bg="white")
        notebook.add(networks_frame, text="📋 Networks")
        
        # Treeview for networks
        tree_frame = tk.Frame(networks_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Scrollbars
        tree_scroll_y = tk.Scrollbar(tree_frame)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        tree_scroll_x = tk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("SSID", "BSSID", "Signal", "Channel", "Security"),
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set
        )
        
        tree_scroll_y.config(command=self.tree.yview)
        tree_scroll_x.config(command=self.tree.xview)
        
        # Define columns
        self.tree.heading("SSID", text="Network Name (SSID)")
        self.tree.heading("BSSID", text="MAC Address (BSSID)")
        self.tree.heading("Signal", text="Signal Strength")
        self.tree.heading("Channel", text="Channel")
        self.tree.heading("Security", text="Security")
        
        self.tree.column("SSID", width=200)
        self.tree.column("BSSID", width=150)
        self.tree.column("Signal", width=150)
        self.tree.column("Channel", width=100)
        self.tree.column("Security", width=150)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Channel Analysis Tab
        analysis_frame = tk.Frame(notebook, bg="white")
        notebook.add(analysis_frame, text="📊 Channel Analysis")
        
        self.analysis_text = scrolledtext.ScrolledText(
            analysis_frame,
            font=("Courier", 10),
            bg="white",
            fg="#1f2937",
            padx=10,
            pady=10
        )
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Debug Tab
        debug_frame = tk.Frame(notebook, bg="white")
        notebook.add(debug_frame, text="🐛 Debug Log")
        
        self.debug_text = scrolledtext.ScrolledText(
            debug_frame,
            font=("Courier", 9),
            bg="#1f2937",
            fg="#10b981",
            padx=10,
            pady=10
        )
        self.debug_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # System Info Tab
        info_frame = tk.Frame(notebook, bg="white")
        notebook.add(info_frame, text="ℹ️ System Info")
        
        info_text = scrolledtext.ScrolledText(
            info_frame,
            font=("Courier", 10),
            bg="white",
            fg="#1f2937",
            padx=10,
            pady=10
        )
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        system_info = f"""
System Information
{'='*60}

Operating System: {self.scanner.system}
Python Version: {platform.python_version()}
Machine: {platform.machine()}
Processor: {platform.processor()}

Scanning Method:
"""
        if self.scanner.system == "Windows":
            system_info += "  • Using 'netsh wlan show networks mode=bssid'\n"
        elif self.scanner.system == "Linux":
            system_info += "  • Using 'nmcli dev wifi list'\n"
            system_info += "  • Note: Install 'network-manager' if not available\n"
        elif self.scanner.system == "Darwin":
            system_info += "  • Using airport utility\n"
        
        system_info += f"\n{'='*60}\n\nClick 'Scan Networks' to begin!"
        
        info_text.insert(1.0, system_info)
        info_text.config(state=tk.DISABLED)
        
    def create_stat_card(self, parent, title, value, color):
        """Create a statistics card"""
        card = tk.Frame(parent, bg=color, relief=tk.RAISED, borderwidth=1)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        title_label = tk.Label(card, text=title, font=("Arial", 10), bg=color, fg="white")
        title_label.pack(pady=(10, 5))
        
        value_label = tk.Label(card, text=value, font=("Arial", 24, "bold"), bg=color, fg="white")
        value_label.pack(pady=(0, 10))
        
        return value_label
    
    def show_debug(self):
        """Show debug information"""
        self.debug_text.delete(1.0, tk.END)
        debug_info = f"""
=== DEBUG INFORMATION ===
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
OS: {self.scanner.system}
Networks Found: {len(self.networks)}

Raw Network Data:
"""
        for i, net in enumerate(self.networks, 1):
            debug_info += f"\nNetwork {i}:\n"
            for key, value in net.items():
                debug_info += f"  {key}: {value}\n"
        
        if not self.networks:
            debug_info += "\nNo networks found. Try clicking 'Scan Networks' first.\n"
            debug_info += "\nIf scanning fails:\n"
            debug_info += "- Windows: Check if Wi-Fi adapter is enabled\n"
            debug_info += "- Linux: Install network-manager (sudo apt install network-manager)\n"
            debug_info += "- macOS: Verify airport utility is available\n"
        
        self.debug_text.insert(1.0, debug_info)
    
    def start_scan(self):
        """Start network scanning in a separate thread"""
        if not self.scanning:
            self.scanning = True
            self.scan_button.config(state=tk.DISABLED, text="⏳ Scanning...")
            self.status_label.config(text="Scanning networks... Please wait")
            self.debug_text.insert(tk.END, f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting scan...\n")
            threading.Thread(target=self.scan_networks, daemon=True).start()
    
    def scan_networks(self):
        """Scan networks and update UI"""
        try:
            self.networks = self.scanner.scan_networks()
            self.root.after(0, self.update_ui)
        except Exception as e:
            error_msg = f"Error scanning networks: {e}"
            self.root.after(0, lambda: self.debug_text.insert(tk.END, f"\n[ERROR] {error_msg}\n"))
            self.root.after(0, lambda: messagebox.showerror("Scan Error", error_msg))
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL, text="🔍 Scan Networks"))
    
    def update_ui(self):
        """Update UI with scan results"""
        # Clear treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.debug_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(self.networks)} networks\n")
        
        if not self.networks:
            self.status_label.config(text="No networks found - Check debug tab for details")
            self.show_debug()
            return
        
        # Sort by signal strength
        sorted_networks = sorted(self.networks, key=lambda x: x.get('signal', 0), reverse=True)
        
        # Update treeview
        for net in sorted_networks:
            ssid = net.get('ssid', 'N/A')
            bssid = net.get('bssid', 'N/A')
            signal = net.get('signal', 0)
            
            if isinstance(signal, int):
                if signal > 70:
                    quality = "Excellent"
                elif signal > 50:
                    quality = "Good"
                elif signal > 30:
                    quality = "Fair"
                else:
                    quality = "Weak"
                signal_str = f"{signal}% ({quality})"
            else:
                signal_str = str(signal)
            
            channel = str(net.get('channel', 'N/A'))
            security = net.get('security', 'N/A')
            
            self.tree.insert("", tk.END, values=(ssid, bssid, signal_str, channel, security))
        
        # Update stats
        secure_count = sum(1 for n in self.networks if n.get('security', 'Open') not in ['Open', 'N/A', ''])
        open_count = len(self.networks) - secure_count
        
        channels = set(str(n.get('channel', 'N/A')) for n in self.networks if n.get('channel') not in ['N/A', ''])
        
        self.total_networks_label.config(text=str(len(self.networks)))
        self.secure_networks_label.config(text=str(secure_count))
        self.open_networks_label.config(text=str(open_count))
        self.channels_label.config(text=str(len(channels)))
        
        # Update channel analysis
        self.update_channel_analysis()
        
        self.status_label.config(
            text=f"Last scan: {datetime.now().strftime('%H:%M:%S')} - Found {len(self.networks)} networks"
        )
        
        self.debug_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] UI updated successfully\n")
    
    def update_channel_analysis(self):
        """Update channel congestion analysis"""
        self.analysis_text.config(state=tk.NORMAL)
        self.analysis_text.delete(1.0, tk.END)
        
        channel_count = defaultdict(int)
        for net in self.networks:
            if 'channel' in net and net['channel'] not in ['N/A', '']:
                try:
                    channel = int(net['channel']) if isinstance(net['channel'], str) else net['channel']
                    channel_count[channel] += 1
                except:
                    pass
        
        analysis = f"""
Channel Congestion Analysis
{'='*60}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Networks: {len(self.networks)}

"""
        
        if channel_count:
            analysis += "Channel Usage:\n"
            analysis += f"{'-'*60}\n"
            
            for channel in sorted(channel_count.keys()):
                count = channel_count[channel]
                bar = '█' * count
                analysis += f"Channel {channel:>3}: {bar} ({count} networks)\n"
            
            analysis += f"\n{'-'*60}\n"
            most_congested = max(channel_count.items(), key=lambda x: x[1])
            analysis += f"\n⚠️  Most Congested: Channel {most_congested[0]} ({most_congested[1]} networks)\n"
            
            # Recommendations
            optimal_2ghz = [1, 6, 11]
            available = [ch for ch in optimal_2ghz if ch not in channel_count or channel_count[ch] <= 2]
            if available:
                analysis += f"\n✅ Recommended 2.4GHz Channels: {', '.join(map(str, available))}\n"
                analysis += "   (These channels have minimal interference)\n"
        else:
            analysis += "No channel data available.\n"
            analysis += "This may mean:\n"
            analysis += "- No networks were found\n"
            analysis += "- Channel information is not available\n"
        
        analysis += f"\n{'='*60}\n"
        
        self.analysis_text.insert(1.0, analysis)
        self.analysis_text.config(state=tk.DISABLED)
    
    def toggle_auto_scan(self):
        """Toggle automatic scanning"""
        if self.auto_scan_var.get():
            self.auto_scan()
        
    def auto_scan(self):
        """Automatically scan every 10 seconds"""
        if self.auto_scan_var.get():
            self.start_scan()
            self.root.after(10000, self.auto_scan)

def main():
    root = tk.Tk()
    app = WiFiScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
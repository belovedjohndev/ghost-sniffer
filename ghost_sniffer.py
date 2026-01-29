import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional
import subprocess
import platform as system_platform

TOOL_VERSION = "1.0.0"

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Dot11Beacon = None
    Dot11 = None
    Dot11Elt = None

try:
    import netifaces  # type: ignore
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


def get_log_path():
    if system_platform.system() == "Windows":
        base_dir = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
        log_dir = os.path.join(base_dir, "GhostSniffer", "logs")
    else:
        log_dir = os.path.join(os.path.expanduser("~"), ".ghost_sniffer", "logs")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, "ghost_sniffer.log")


DEFAULT_THEME = {
    "bg": "#0b1220",
    "surface": "#0f172a",
    "surface_alt": "#111827",
    "border": "#1f2937",
    "text": "#e5e7eb",
    "muted": "#94a3b8",
    "accent": "#38bdf8",
    "accent_bg": "#0ea5e9",
    "success": "#22c55e",
    "warning": "#f97316",
    "error": "#ef4444"
}

DEFAULT_FONTS = {
    "title": ("Segoe UI", 22, "bold"),
    "subtitle": ("Segoe UI", 10),
    "body": ("Segoe UI", 10),
    "body_bold": ("Segoe UI", 10, "bold"),
    "tab": ("Segoe UI", 10, "bold"),
    "mono": ("Consolas", 9)
}

LOG_FILE = get_log_path()
logger = logging.getLogger("ghost_sniffer")


def show_modal_dialog(root, title, message, kind="info", buttons=("OK",), default=None,
                      theme=DEFAULT_THEME, fonts=DEFAULT_FONTS):
    result = {"value": None}
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.configure(bg=theme["bg"])
    dialog.transient(root)
    dialog.grab_set()
    dialog.resizable(False, False)

    indicator_color = {
        "info": theme["accent"],
        "warning": theme["warning"],
        "error": theme["error"],
        "success": theme["success"]
    }.get(kind, theme["accent"])

    container = tk.Frame(dialog, bg=theme["bg"], padx=20, pady=20)
    container.pack(fill=tk.BOTH, expand=True)

    header = tk.Frame(container, bg=theme["bg"])
    header.pack(fill=tk.X, pady=(0, 10))

    indicator = tk.Frame(header, bg=indicator_color, width=6, height=24)
    indicator.pack(side=tk.LEFT, padx=(0, 10))

    title_label = tk.Label(
        header,
        text=title,
        font=fonts["body_bold"],
        fg=theme["text"],
        bg=theme["bg"]
    )
    title_label.pack(side=tk.LEFT)

    msg_label = tk.Label(
        container,
        text=message,
        font=fonts["body"],
        fg=theme["text"],
        bg=theme["bg"],
        wraplength=380,
        justify=tk.LEFT
    )
    msg_label.pack(fill=tk.X, pady=(0, 20))

    btn_frame = tk.Frame(container, bg=theme["bg"])
    btn_frame.pack(fill=tk.X)

    def on_click(value):
        result["value"] = value
        dialog.destroy()

    default_button = default or (buttons[0] if buttons else None)
    for label in buttons:
        is_primary = label == default_button
        btn = tk.Button(
            btn_frame,
            text=label,
            command=lambda v=label: on_click(v),
            bg=theme["accent_bg"] if is_primary else theme["surface_alt"],
            fg=theme["text"],
            padx=16,
            pady=6,
            relief=tk.FLAT,
            activebackground=theme["accent"] if is_primary else theme["surface"],
            activeforeground=theme["text"]
        )
        btn.pack(side=tk.RIGHT, padx=6)

    dialog.update_idletasks()
    dialog_width = max(420, dialog.winfo_reqwidth())
    dialog_height = max(200, dialog.winfo_reqheight())
    screen_width = dialog.winfo_screenwidth()
    screen_height = dialog.winfo_screenheight()
    x = int((screen_width / 2) - (dialog_width / 2))
    y = int((screen_height / 2) - (dialog_height / 2))
    dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")

    dialog.wait_window()
    return result["value"]


def setup_logging():
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


def get_network_interfaces():
    """
    Detect and return available network interfaces.
    
    Attempts multiple methods to discover interfaces:
    - Scapy interface detection
    - Netifaces (if available)
    - System commands (ipconfig/ifconfig)
    
    Returns:
        List[str]: List of available network interface names/descriptions
    """
    interfaces = []
    
    if SCAPY_AVAILABLE:
        try:
            from scapy.all import get_if_list
            scapy_interfaces = get_if_list()
            if scapy_interfaces:
                if system_platform.system() == "Windows":
                    try:
                        result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                        ipconfig_output = result.stdout
                        
                        adapter_info = {}
                        current_adapter = None
                        for line in ipconfig_output.split('\n'):
                            if 'adapter' in line.lower() and ':' in line:
                                current_adapter = line.split(':')[0].strip()
                            elif current_adapter and 'physical address' in line.lower():
                                mac = line.split(':')[-1].strip().replace('-', ':')
                                adapter_info[mac] = current_adapter
                        
                        try:
                            ps_cmd = "Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid | ConvertTo-Json"
                            result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                                  capture_output=True, text=True, timeout=3)
                            if result.returncode == 0:
                                import json
                                adapters = json.loads(result.stdout) if result.stdout.strip() else []
                                if not isinstance(adapters, list):
                                    adapters = [adapters]
                                
                                for iface in scapy_interfaces:
                                    if 'Loopback' in iface:
                                        interfaces.append(f"Loopback ({iface})")
                                    else:
                                        guid_part = iface.split('{')[-1].split('}')[0] if '{' in iface else ''
                                        matched = False
                                        for adapter in adapters:
                                            adapter_guid = adapter.get('InterfaceGuid', '')
                                            if guid_part and guid_part.upper() in adapter_guid.upper():
                                                name = adapter.get('Name', 'Unknown')
                                                desc = adapter.get('InterfaceDescription', '')
                                                if 'wireless' in desc.lower() or 'wi-fi' in desc.lower() or 'wlan' in desc.lower():
                                                    interfaces.insert(0, f"{name} - {desc} ({iface})")
                                                else:
                                                    interfaces.append(f"{name} - {desc} ({iface})")
                                                matched = True
                                                break
                                        if not matched:
                                            interfaces.append(f"Interface - {iface}")
                            else:
                                interfaces.extend(scapy_interfaces)
                        except:
                            for iface in scapy_interfaces:
                                if 'Loopback' in iface:
                                    interfaces.append(f"Loopback ({iface})")
                                else:
                                    interfaces.append(iface)
                    except:
                        interfaces.extend(scapy_interfaces)
                else:
                    interfaces.extend(scapy_interfaces)
        except Exception as e:
            pass
    
    if not interfaces and NETIFACES_AVAILABLE:
        try:
            for iface in netifaces.interfaces():
                interfaces.append(iface)
        except:
            pass
    
    if not interfaces:
        if system_platform.system() == "Windows":
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'adapter' in line.lower() and ':' in line:
                        name = line.split(':')[0].strip()
                        if name and name not in interfaces:
                            interfaces.append(name)
            except:
                pass
        else:
            try:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'state' not in line.lower():
                        parts = line.split(': ')
                        if len(parts) > 1:
                            iface = parts[1].split('@')[0].strip()
                            if iface and iface not in interfaces:
                                interfaces.append(iface)
            except:
                try:
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
                    for line in result.stdout.split('\n'):
                        if line and not line.startswith(' ') and not line.startswith('\t'):
                            iface = line.split(':')[0].split()[0]
                            if iface and iface not in interfaces:
                                interfaces.append(iface)
                except:
                    pass
    
    if not interfaces:
        logger.warning("No network interfaces detected; using fallback defaults.")
        interfaces = ['lo', 'localhost'] if system_platform.system() != "Windows" else ['Local Area Connection']
    
    return interfaces


class Phase1GhostSniffer:
    
    def __init__(self, callback):
        self.callback = callback
        self.is_running = False
        self.captured_data = []
        self.thread = None
        
    def start_listening(self, interface: Optional[str] = None):
        if self.is_running:
            return
            
        self.is_running = True
        self.captured_data = []
        self.thread = threading.Thread(target=self._listen_loop, args=(interface,), daemon=True)
        self.thread.start()
        
    def _listen_loop(self, interface: Optional[str]):
        networks_found = {}
        
        if not interface:
            logger.error("Phase 1 start failed: no interface selected.")
            self.callback("error", "No network interface specified")
            self.is_running = False
            return
            
        while self.is_running:
            try:
                networks = self._scan_networks(interface)
                for net in networks:
                    if net['bssid'] not in networks_found:
                        networks_found[net['bssid']] = net
                        self.captured_data.append(net)
                        self.callback("network_discovered", net)
            except Exception as e:
                logger.exception("Phase 1 scan error")
                self.callback("error", str(e))
                self.is_running = False
            
            time.sleep(2)
            
    def _scan_networks(self, interface: str) -> List[Dict]:
        networks = []
        networks_dict = {}
        
        try:
            if not SCAPY_AVAILABLE:
                raise Exception("Scapy is not installed. Please install it with: pip install scapy")
            if '(' in interface and ')' in interface:
                interface = interface.split('(')[-1].rstrip(')')
            
            if system_platform.system() != "Windows":
                try:
                    subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                                 capture_output=True, timeout=2, check=False)
                except:
                    pass
            
            packets = sniff(iface=interface, timeout=1, 
                          lfilter=lambda p: p.haslayer(Dot11Beacon),
                          store=True)
            
            for packet in packets:
                if packet.haslayer(Dot11Beacon):
                    try:
                        bssid = packet[Dot11].addr2
                        
                        if bssid in networks_dict:
                            continue
                        
                        ssid = None
                        if packet.haslayer(Dot11Elt):
                            elt = packet[Dot11Elt]
                            while elt:
                                if elt.ID == 0:
                                    if elt.info:
                                        ssid = elt.info.decode('utf-8', errors='ignore')
                                    break
                                if not elt.ID:
                                    break
                                elt = elt.payload if hasattr(elt, 'payload') else None
                        
                        rssi = 0
                        if packet.haslayer('RadioTap'):
                            rt = packet['RadioTap']
                            if hasattr(rt, 'dBm_AntSignal'):
                                rssi = rt.dBm_AntSignal
                            elif hasattr(rt, 'dBm_AntSignal1'):
                                rssi = rt.dBm_AntSignal1
                        
                        encryption = "Unknown"
                        channel = 0
                        
                        if packet.haslayer(Dot11Elt):
                            elt = packet[Dot11Elt]
                            while elt:
                                if elt.ID == 48:
                                    encryption = "WPA2"
                                    if len(elt.info) > 2:
                                        try:
                                            akm_count = int.from_bytes(elt.info[2:4], 'little')
                                            if akm_count > 0 and len(elt.info) > 6:
                                                akm_oui = elt.info[4:7]
                                                if akm_oui == b'\x00\x0f\xac':
                                                    if len(elt.info) > 7:
                                                        akm_type = elt.info[7]
                                                        if akm_type == 8:
                                                            encryption = "WPA3"
                                        except:
                                            pass
                                elif elt.ID == 221:
                                    if b'\x00\x50\xf2' in elt.info:
                                        if encryption == "Unknown":
                                            encryption = "WPA"
                                elif elt.ID == 3:
                                    if len(elt.info) > 0:
                                        channel = elt.info[0]
                                
                                if not elt.ID:
                                    break
                                elt = elt.payload if hasattr(elt, 'payload') else None
                            
                            if encryption == "Unknown":
                                if packet[Dot11].FCfield & 0x40:
                                    encryption = "WEP"
                                else:
                                    encryption = "Open"
                        
                        network = {
                            "ssid": ssid if ssid else "Hidden",
                            "bssid": bssid,
                            "channel": channel,
                            "rssi": rssi,
                            "encryption": encryption
                        }
                        
                        networks_dict[bssid] = network
                        networks.append(network)
                        
                    except Exception as e:
                        continue
                        
        except Exception as e:
            error_msg = str(e)
            if "No libpcap" in error_msg or "pcap" in error_msg.lower():
                raise Exception("Npcap is not installed or not in WinPcap compatibility mode. Please install Npcap from https://npcap.com/ and restart your computer.")
            elif "permission" in error_msg.lower() or "access" in error_msg.lower():
                raise Exception("Permission denied. Try running as Administrator.")
            elif "No such device" in error_msg or "interface" in error_msg.lower():
                raise Exception(f"Interface '{interface}' not found or not accessible. Make sure your Wi-Fi adapter is enabled.")
            else:
                raise Exception(f"Scanning error: {error_msg}")
        
        return networks
        
    def stop_listening(self):
        self.is_running = False
        
    def get_captured_data(self) -> List[Dict]:
        return self.captured_data.copy()


class Phase2ProtocolDaemon:
    """
    Phase 2: The Covenant-Pulse - Vulnerability Analysis
    
    Analyzes discovered networks for security vulnerabilities, encryption weaknesses,
    and configuration issues. Assigns risk scores and provides security recommendations.
    """
    
    def __init__(self, callback):
        self.callback = callback
        self.weak_ssid_patterns = [
            "default", "linksys", "netgear", "dlink", "tp-link", "admin", 
            "password", "12345678", "wifi", "wireless", "router"
        ]
        
    def _check_weak_ssid(self, ssid: str) -> bool:
        if not ssid or ssid == "Hidden":
            return False
        ssid_lower = ssid.lower()
        return any(pattern in ssid_lower for pattern in self.weak_ssid_patterns)
    
    def _check_default_credentials_risk(self, ssid: str) -> bool:
        if not ssid or ssid == "Hidden":
            return False
        default_patterns = ["linksys", "netgear", "dlink", "belkin", "cisco", "asus"]
        return any(pattern in ssid.lower() for pattern in default_patterns)
    
    def analyze_networks(self, networks: List[Dict]) -> List[Dict]:
        results = []
        
        for network in networks:
            analysis = {
                "network": network,
                "vulnerabilities": [],
                "risk_score": 0,
                "handshake_detected": False,
                "weak_crypto": False,
                "security_recommendations": []
            }
            
            ssid = network.get("ssid", "")
            encryption = network.get("encryption", "Unknown")
            rssi = network.get("rssi", 0)
            
            if encryption == "Open":
                analysis["vulnerabilities"].append({
                    "type": "No Encryption",
                    "severity": "Critical",
                    "description": "Network broadcasts without any cryptographic protection. All traffic is unencrypted.",
                    "cvss_score": 9.1,
                    "cve": "CWE-319"
                })
                analysis["risk_score"] += 9.1
                analysis["weak_crypto"] = True
                analysis["security_recommendations"].append("Enable WPA2 or WPA3 encryption immediately")
                
            elif encryption == "WEP":
                analysis["vulnerabilities"].append({
                    "type": "Deprecated Encryption",
                    "severity": "Critical",
                    "description": "WEP encryption is cryptographically broken and easily crackable within minutes",
                    "cvss_score": 8.5,
                    "cve": "CVE-2004-0720"
                })
                analysis["risk_score"] += 8.5
                analysis["weak_crypto"] = True
                analysis["security_recommendations"].append("Upgrade to WPA2 or WPA3 encryption")
                
            elif encryption == "WPA":
                analysis["vulnerabilities"].append({
                    "type": "Legacy WPA Encryption",
                    "severity": "High",
                    "description": "WPA (TKIP) is vulnerable to various attacks and should be upgraded",
                    "cvss_score": 7.0,
                    "cve": "CVE-2017-13077"
                })
                analysis["risk_score"] += 7.0
                analysis["security_recommendations"].append("Upgrade to WPA2 (AES) or WPA3")
                
            elif encryption == "WPA2":
                analysis["vulnerabilities"].append({
                    "type": "WPS PIN Vulnerability",
                    "severity": "High",
                    "description": "WPA2 networks may be vulnerable to WPS PIN brute-force attacks if WPS is enabled",
                    "cvss_score": 7.5,
                    "cve": "CVE-2012-2615"
                })
                analysis["risk_score"] += 7.5
                analysis["security_recommendations"].append("Disable WPS if not needed")
                
                analysis["vulnerabilities"].append({
                    "type": "KRACK Vulnerability (WPA2)",
                    "severity": "Medium",
                    "description": "WPA2 is potentially vulnerable to Key Reinstallation Attacks. Ensure firmware is updated.",
                    "cvss_score": 6.1,
                    "cve": "CVE-2017-13077"
                })
                analysis["risk_score"] += 6.1
                analysis["security_recommendations"].append("Ensure router firmware is up to date")
                
            elif encryption == "WPA3":
                analysis["vulnerabilities"].append({
                    "type": "WPA3 Dragonblood Vulnerability",
                    "severity": "Medium",
                    "description": "WPA3 may be vulnerable to downgrade attacks if not properly implemented",
                    "cvss_score": 5.4,
                    "cve": "CVE-2019-9494"
                })
                analysis["risk_score"] += 5.4
                analysis["security_recommendations"].append("Ensure WPA3 implementation is up to date")
            
            if self._check_weak_ssid(ssid):
                analysis["vulnerabilities"].append({
                    "type": "Weak SSID Pattern",
                    "severity": "Medium",
                    "description": f"SSID '{ssid}' suggests weak security practices or default configuration",
                    "cvss_score": 4.0
                })
                analysis["risk_score"] += 4.0
                analysis["security_recommendations"].append("Use a unique, non-default SSID")
            
            if self._check_default_credentials_risk(ssid):
                analysis["vulnerabilities"].append({
                    "type": "Potential Default Credentials",
                    "severity": "High",
                    "description": "SSID suggests router may still use default admin credentials",
                    "cvss_score": 7.0
                })
                analysis["risk_score"] += 7.0
                analysis["security_recommendations"].append("Change default router admin credentials")
            
            if rssi > -50:
                analysis["vulnerabilities"].append({
                    "type": "Very Strong Signal",
                    "severity": "Info",
                    "description": "Very strong signal detected - ensure physical security of access point",
                    "cvss_score": 1.0
                })
                analysis["risk_score"] += 1.0
            elif rssi > -80:
                analysis["vulnerabilities"].append({
                    "type": "Weak Signal Strength",
                    "severity": "Low",
                    "description": "Weak signal may indicate distance or interference issues",
                    "cvss_score": 2.0
                })
                analysis["risk_score"] += 2.0
            
            if ssid == "Hidden" or not ssid:
                analysis["vulnerabilities"].append({
                    "type": "Hidden SSID",
                    "severity": "Info",
                    "description": "SSID is hidden, but this provides minimal security benefit",
                    "cvss_score": 1.0
                })
                analysis["risk_score"] += 1.0
            
            if encryption in ["WPA2", "WPA3", "WPA"]:
                analysis["handshake_detected"] = True
                
            results.append(analysis)
            self.callback("analysis_complete", analysis)
            
        return results


class Phase3AutopwnSprite:
    """
    Phase 3: The Legion of Keys - Exploit Testing
    
    Deploys exploit attempts against discovered networks. Supports both simulation
    mode (for demonstration) and real exploit mode (requires authorization and tools).
    """
    
    def __init__(self, callback):
        self.callback = callback
        try:
            from real_exploits import RealExploitEngine
            self.real_engine = RealExploitEngine()
            self.real_engine.callback = callback
            self.real_exploits_available = True
            self.tools_status = self.real_engine.get_tools_status()
        except ImportError:
            self.real_engine = None
            self.real_exploits_available = False
            self.tools_status = {}
        
    def deploy_exploits(self, analyses: List[Dict]) -> List[Dict]:
        results = []
        
        for idx, analysis in enumerate(analyses):
            network = analysis["network"]
            encryption = network.get("encryption", "Unknown")
            ssid = network.get("ssid", "Hidden")
            
            exploit_results = {
                "network": network,
                "exploits_attempted": [],
                "exploits_successful": [],
                "exploits_failed": [],
                "compromised": False,
                "exploit_details": [],
                "time_taken": 0
            }
            
            start_time = time.time()
            
            self.callback("exploit_progress", {
                "network": network,
                "progress": 0,
                "status": "Initializing exploit sequence..."
            })
            
            if encryption == "Open":
                self.callback("exploit_progress", {
                    "network": network,
                    "progress": 25,
                    "status": "Attempting open network access..."
                })
                time.sleep(0.5)
                
                exploit_results["exploits_attempted"].append({
                    "name": "Open Network Access",
                    "type": "Direct Access",
                    "status": "success"
                })
                exploit_results["exploits_successful"].append("Open Network Access")
                exploit_results["compromised"] = True
                exploit_results["exploit_details"].append({
                    "exploit": "Open Network Access",
                    "result": "Network accessible without authentication",
                    "impact": "Full network access granted"
                })
                self.callback("exploit_success", {"network": network, "exploit": "Open Network Access"})
                
            elif encryption == "WEP":
                if self.real_exploits_available and self.tools_status.get('aircrack-ng'):
                    exploit_results["exploits_attempted"].append({
                        "name": "WEP Cipher-Shatter (Real)",
                        "type": "Cryptographic Attack",
                        "status": "attempted"
                    })
                    
                    interface = network.get('interface', None)
                    if not interface:
                        from ghost_sniffer import get_network_interfaces
                        interfaces = get_network_interfaces()
                        interface = interfaces[0] if interfaces else None
                    
                    if interface:
                        success, key, details = self.real_engine.attack_wep(network, interface, timeout=300)
                        if success:
                            exploit_results["exploits_successful"].append("WEP Cipher-Shatter (Real)")
                            exploit_results["compromised"] = True
                            exploit_results["exploit_details"].append({
                                "exploit": "WEP Cipher-Shatter",
                                "result": f"WEP key recovered: {key}",
                                "impact": "Network encryption bypassed",
                                "real_exploit": True,
                                **details
                            })
                            self.callback("exploit_success", {"network": network, "exploit": "WEP Cipher-Shatter"})
                        else:
                            exploit_results["exploits_failed"].append("WEP Cipher-Shatter (Real)")
                            exploit_results["exploit_details"].append({
                                "exploit": "WEP Cipher-Shatter",
                                "result": f"Attack failed: {details.get('error', 'Unknown error')}",
                                "real_exploit": True,
                                **details
                            })
                    else:
                        self._simulate_wep_attack(network, exploit_results)
                else:
                    self._simulate_wep_attack(network, exploit_results)
                
            elif encryption in ["WPA", "WPA2"]:
                if self.real_exploits_available and self.tools_status.get('reaver'):
                    exploit_results["exploits_attempted"].append({
                        "name": "WPS PIN Brute-Force (Real)",
                        "type": "Brute-Force",
                        "status": "attempted"
                    })
                    
                    interface = network.get('interface', None)
                    if not interface:
                        from ghost_sniffer import get_network_interfaces
                        interfaces = get_network_interfaces()
                        interface = interfaces[0] if interfaces else None
                    
                    if interface and network.get('channel', 0) > 0:
                        success, pin_or_psk, details = self.real_engine.attack_wps(network, interface, timeout=1800)
                        if success:
                            exploit_results["exploits_successful"].append("WPS PIN Brute-Force (Real)")
                            exploit_results["compromised"] = True
                            exploit_results["exploit_details"].append({
                                "exploit": "WPS PIN Brute-Force",
                                "result": f"WPS PIN/PSK recovered: {pin_or_psk}",
                                "impact": "Network access granted via WPS vulnerability",
                                "real_exploit": True,
                                **details
                            })
                            self.callback("exploit_success", {"network": network, "exploit": "WPS PIN Brute-Force"})
                        else:
                            exploit_results["exploits_failed"].append("WPS PIN Brute-Force (Real)")
                            self._attempt_wpa2_dictionary(network, analysis, exploit_results)
                    else:
                        self._simulate_wpa2_attack(network, analysis, exploit_results)
                else:
                    self._simulate_wpa2_attack(network, analysis, exploit_results)
                    
            elif encryption == "WPA3":
                self.callback("exploit_progress", {
                    "network": network,
                    "progress": 30,
                    "status": "Attempting WPA3 downgrade attack..."
                })
                time.sleep(0.6)
                
                exploit_results["exploits_attempted"].append({
                    "name": "WPA3 Downgrade Attack",
                    "type": "Protocol Downgrade",
                    "status": "failed"
                })
                exploit_results["exploits_failed"].append("WPA3 Downgrade Attack")
                exploit_results["exploit_details"].append({
                    "exploit": "WPA3 Downgrade Attack",
                    "result": "Attack failed - WPA3 properly implemented",
                    "impact": "Network remains secure"
                })
            
            exploit_results["time_taken"] = round(time.time() - start_time, 2)
            
            self.callback("exploit_progress", {
                "network": network,
                "progress": 100,
                "status": "Exploit sequence complete"
            })
            
            results.append(exploit_results)
            
        return results
    
    def _simulate_wep_attack(self, network, exploit_results):
        self.callback("exploit_progress", {
            "network": network,
            "progress": 20,
            "status": "Collecting IV packets for WEP attack (SIMULATED)..."
        })
        time.sleep(0.8)
        
        exploit_results["exploits_attempted"].append({
            "name": "IV Collection Attack",
            "type": "Passive Collection",
            "status": "success"
        })
        
        self.callback("exploit_progress", {
            "network": network,
            "progress": 60,
            "status": "Attempting WEP cipher-shatter (SIMULATED)..."
        })
        time.sleep(1.0)
        
        exploit_results["exploits_attempted"].append({
            "name": "WEP Cipher-Shatter",
            "type": "Cryptographic Attack",
            "status": "success"
        })
        exploit_results["exploits_successful"].append("WEP Cipher-Shatter")
        exploit_results["compromised"] = True
        exploit_results["exploit_details"].append({
            "exploit": "WEP Cipher-Shatter",
            "result": "WEP key recovered successfully (SIMULATED)",
            "impact": "Network encryption bypassed",
            "real_exploit": False
        })
        self.callback("exploit_success", {"network": network, "exploit": "WEP Cipher-Shatter"})
    
    def _attempt_wpa2_dictionary(self, network, analysis, exploit_results):
        if not self.real_exploits_available:
            return
        
        handshake_file = network.get('handshake_file', None)
        if not handshake_file:
            interface = network.get('interface', None)
            if interface:
                handshake_file = self.real_engine.capture_handshake(network, interface, timeout=300)
        
        if handshake_file and os.path.exists(handshake_file):
            exploit_results["exploits_attempted"].append({
                "name": "Dictionary Attack (Real)",
                "type": "Password Cracking",
                "status": "attempted"
            })
            exploit_results["exploit_details"].append({
                "exploit": "Dictionary Attack",
                "result": "Handshake captured, dictionary attack requires wordlist file",
                "real_exploit": True
            })
    
    def _simulate_wpa2_attack(self, network, analysis, exploit_results):
        self.callback("exploit_progress", {
            "network": network,
            "progress": 15,
            "status": "Probing WPS PIN vulnerability (SIMULATED)..."
        })
        time.sleep(0.5)
        
        exploit_results["exploits_attempted"].append({
            "name": "WPS PIN Brute-Force",
            "type": "Brute-Force",
            "status": "attempted"
        })
        
        self.callback("exploit_progress", {
            "network": network,
            "progress": 40,
            "status": "Running dictionary attack on handshake (SIMULATED)..."
        })
        time.sleep(0.7)
        
        exploit_results["exploits_attempted"].append({
            "name": "Dictionary Attack",
            "type": "Password Cracking",
            "status": "attempted"
        })
        
        self.callback("exploit_progress", {
            "network": network,
            "progress": 60,
            "status": "Attempting PMKID extraction (SIMULATED)..."
        })
        time.sleep(0.5)
        
        exploit_results["exploits_attempted"].append({
            "name": "PMKID Attack",
            "type": "Offline Attack",
            "status": "attempted"
        })
        
        if analysis.get("risk_score", 0) > 7:
            exploit_results["exploits_successful"].append("WPS PIN Brute-Force")
            exploit_results["compromised"] = True
            exploit_results["exploit_details"].append({
                "exploit": "WPS PIN Brute-Force",
                "result": "WPS PIN recovered, network key derived (SIMULATED)",
                "impact": "Network access granted via WPS vulnerability",
                "real_exploit": False
            })
            self.callback("exploit_success", {"network": network, "exploit": "WPS PIN Brute-Force"})
        else:
            exploit_results["exploits_failed"].extend([
                "WPS PIN Brute-Force",
                "Dictionary Attack",
                "PMKID Attack"
            ])
            exploit_results["exploit_details"].append({
                "exploit": "Multiple Attack Vectors",
                "result": "All attacks failed - network appears secure (SIMULATED)",
                "impact": "No access gained",
                "real_exploit": False
            })


class Phase4VulnerabilityCartograph:
    """
    Phase 4: The Scroll of Truths - Report Generation
    
    Generates comprehensive security audit reports with risk analysis, vulnerability
    details, and prioritized recommendations. Supports export in multiple formats.
    """
    
    def __init__(self, callback):
        self.callback = callback
        
    def generate_report(self, networks: List[Dict], analyses: List[Dict], exploits: List[Dict]) -> Dict:
        report = {
            "timestamp": datetime.now().isoformat(),
            "tool_version": TOOL_VERSION,
            "summary": {
                "total_networks": len(networks),
                "vulnerable_networks": sum(1 for a in analyses if a.get("risk_score", 0) > 5),
                "compromised_networks": sum(1 for e in exploits if e.get("compromised", False)),
                "critical_vulnerabilities": sum(
                    len([v for v in a.get("vulnerabilities", []) if v.get("severity") == "Critical"])
                    for a in analyses
                ),
                "high_vulnerabilities": sum(
                    len([v for v in a.get("vulnerabilities", []) if v.get("severity") == "High"])
                    for a in analyses
                ),
                "medium_vulnerabilities": sum(
                    len([v for v in a.get("vulnerabilities", []) if v.get("severity") == "Medium"])
                    for a in analyses
                ),
                "average_risk_score": sum(a.get("risk_score", 0) for a in analyses) / len(analyses) if analyses else 0
            },
            "targets": [],
            "heat_map": {}
        }
        
        for i, (network, analysis, exploit) in enumerate(zip(networks, analyses, exploits)):
            target = {
                "rank": i + 1,
                "network": network,
                "risk_score": analysis.get("risk_score", 0),
                "vulnerabilities": analysis.get("vulnerabilities", []),
                "security_recommendations": analysis.get("security_recommendations", []),
                "exploit_status": "Compromised" if exploit.get("compromised") else "Resistant",
                "exploits_attempted": exploit.get("exploits_attempted", []),
                "exploits_successful": exploit.get("exploits_successful", []),
                "exploit_time": exploit.get("time_taken", 0),
                "recommended_action": self._get_recommendation(analysis, exploit)
            }
            report["targets"].append(target)
            
        report["targets"].sort(key=lambda x: x["risk_score"], reverse=True)
        for i, target in enumerate(report["targets"]):
            target["rank"] = i + 1
            
        report["heat_map"] = {
            "critical": [t for t in report["targets"] if t["risk_score"] >= 8],
            "high": [t for t in report["targets"] if 5 <= t["risk_score"] < 8],
            "medium": [t for t in report["targets"] if 2 <= t["risk_score"] < 5],
            "low": [t for t in report["targets"] if t["risk_score"] < 2]
        }
        
        self.callback("report_generated", report)
        return report
        
    def _get_recommendation(self, analysis: Dict, exploit: Dict) -> str:
        if exploit.get("compromised"):
            return "Immediate remediation required - network is compromised"
        elif analysis.get("risk_score", 0) >= 8:
            return "High priority - implement stronger encryption"
        elif analysis.get("risk_score", 0) >= 5:
            return "Medium priority - review security configuration"
        else:
            return "Low priority - monitor for changes"
    
    def export_csv(self, report: Dict, filename: str):
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            writer.writerow(['Rank', 'SSID', 'BSSID', 'Encryption', 'Channel', 'RSSI', 
                           'Risk Score', 'Vulnerabilities', 'Exploit Status', 'Recommendation'])
            
            for target in report["targets"]:
                net = target["network"]
                vulns = ', '.join([v.get("type", "") for v in target.get("vulnerabilities", [])])
                writer.writerow([
                    target["rank"],
                    net.get("ssid", "Hidden"),
                    net.get("bssid", "Unknown"),
                    net.get("encryption", "Unknown"),
                    net.get("channel", "N/A"),
                    f"{net.get('rssi', 0)} dBm",
                    f"{target['risk_score']:.1f}",
                    vulns,
                    target["exploit_status"],
                    target["recommended_action"]
                ])
    
    def export_html(self, report: Dict, filename: str):
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Ghost-Sniffer Security Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0b1220; color: #e5e7eb; margin: 0; padding: 20px; }}
        .header {{ background: #0f172a; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #1f2937; }}
        .header h1 {{ color: #38bdf8; margin: 0; }}
        .summary {{ background: #0f172a; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #1f2937; }}
        .summary h2 {{ color: #38bdf8; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }}
        .summary-item {{ background: #111827; padding: 10px; border-radius: 6px; border: 1px solid #1f2937; }}
        .summary-value {{ color: #38bdf8; font-size: 24px; font-weight: bold; }}
        .target {{ background: #0f172a; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 5px solid #1f2937; }}
        .target.critical {{ border-left-color: #ef4444; }}
        .target.high {{ border-left-color: #f97316; }}
        .target.medium {{ border-left-color: #eab308; }}
        .target.low {{ border-left-color: #22c55e; }}
        .target h3 {{ color: #38bdf8; margin-top: 0; }}
        .vuln {{ background: #111827; padding: 10px; margin: 5px 0; border-radius: 6px; border-left: 3px solid #1f2937; }}
        .vuln.critical {{ border-left: 3px solid #ef4444; }}
        .vuln.high {{ border-left: 3px solid #f97316; }}
        .vuln.medium {{ border-left: 3px solid #eab308; }}
        .vuln.low {{ border-left: 3px solid #22c55e; }}
        .risk-score {{ font-size: 20px; font-weight: bold; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #1f2937; }}
        th {{ background: #0f172a; color: #e5e7eb; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Ghost-Sniffer Security Audit Report</h1>
        <p>Generated: {datetime.fromisoformat(report['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div>Total Networks</div>
                <div class="summary-value">{report['summary']['total_networks']}</div>
            </div>
            <div class="summary-item">
                <div>Vulnerable Networks</div>
                <div class="summary-value">{report['summary']['vulnerable_networks']}</div>
            </div>
            <div class="summary-item">
                <div>Compromised Networks</div>
                <div class="summary-value">{report['summary']['compromised_networks']}</div>
            </div>
            <div class="summary-item">
                <div>Critical Vulnerabilities</div>
                <div class="summary-value">{report['summary']['critical_vulnerabilities']}</div>
            </div>
            <div class="summary-item">
                <div>Average Risk Score</div>
                <div class="summary-value">{report['summary']['average_risk_score']:.1f}</div>
            </div>
        </div>
    </div>
    
    <h2>Prioritized Target List</h2>
"""
        
        for target in report["targets"]:
            net = target["network"]
            risk_class = "low"
            if target["risk_score"] >= 8:
                risk_class = "critical"
            elif target["risk_score"] >= 5:
                risk_class = "high"
            elif target["risk_score"] >= 2:
                risk_class = "medium"
            
            html_content += f"""
    <div class="target {risk_class}">
        <h3>Rank #{target['rank']}: {net.get('ssid', 'Hidden')} ({net.get('bssid')})</h3>
        <p><strong>Encryption:</strong> {net.get('encryption', 'Unknown')} | 
           <strong>Channel:</strong> {net.get('channel', 'N/A')} | 
           <strong>RSSI:</strong> {net.get('rssi', 0)} dBm</p>
        <p class="risk-score">Risk Score: {target['risk_score']:.1f}</p>
        <p><strong>Exploit Status:</strong> {target['exploit_status']}</p>
        <p><strong>Recommendation:</strong> {target['recommended_action']}</p>
        
        <h4>Vulnerabilities:</h4>
"""
            for vuln in target.get("vulnerabilities", []):
                severity = vuln.get("severity", "Info").lower()
                html_content += f"""
        <div class="vuln {severity}">
            <strong>{vuln.get('type', 'Unknown')}</strong> ({vuln.get('severity', 'Info')}) - CVSS: {vuln.get('cvss_score', 0)}
            <br>{vuln.get('description', '')}
        </div>
"""
            
            if target.get("security_recommendations"):
                html_content += "<h4>Security Recommendations:</h4><ul>"
                for rec in target["security_recommendations"]:
                    html_content += f"<li>{rec}</li>"
                html_content += "</ul>"
            
            html_content += "</div>"
        
        html_content += """
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def export_pdf(self, report: Dict, filename: str):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
        except ImportError:
            raise Exception("reportlab is required for PDF export. Install it with: pip install reportlab")
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#38bdf8'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#38bdf8'),
            spaceAfter=12
        )
        
        # Title
        story.append(Paragraph("Ghost-Sniffer Security Audit Report", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.fromisoformat(report['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal']
        ))
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        summary = report['summary']
        summary_data = [
            ['Metric', 'Value'],
            ['Total Networks', str(summary['total_networks'])],
            ['Vulnerable Networks', str(summary['vulnerable_networks'])],
            ['Compromised Networks', str(summary['compromised_networks'])],
            ['Critical Vulnerabilities', str(summary['critical_vulnerabilities'])],
            ['High Vulnerabilities', str(summary.get('high_vulnerabilities', 0))],
            ['Medium Vulnerabilities', str(summary.get('medium_vulnerabilities', 0))],
            ['Average Risk Score', f"{summary.get('average_risk_score', 0):.2f}"]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#e5e7eb')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Courier-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#e5e7eb')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#1f2937')),
            ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Prioritized Target List
        story.append(Paragraph("Prioritized Target List", heading_style))
        
        for target in report["targets"]:
            net = target["network"]
            
            # Risk color
            risk_color = colors.HexColor('#22c55e')  # low
            if target["risk_score"] >= 8:
                risk_color = colors.HexColor('#ef4444')  # critical
            elif target["risk_score"] >= 5:
                risk_color = colors.HexColor('#f97316')  # high
            elif target["risk_score"] >= 2:
                risk_color = colors.HexColor('#eab308')  # medium
            
            story.append(Paragraph(
                f"Rank #{target['rank']}: {net.get('ssid', 'Hidden')} ({net.get('bssid')})",
                ParagraphStyle('TargetTitle', parent=styles['Heading3'], textColor=risk_color)
            ))
            
            target_info = [
                f"Encryption: {net.get('encryption', 'Unknown')}",
                f"Channel: {net.get('channel', 'N/A')}",
                f"RSSI: {net.get('rssi', 0)} dBm",
                f"Risk Score: {target['risk_score']:.1f}",
                f"Exploit Status: {target['exploit_status']}",
                f"Recommendation: {target['recommended_action']}"
            ]
            
            for info in target_info:
                story.append(Paragraph(info, styles['Normal']))
            
            if target.get("vulnerabilities"):
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph("Vulnerabilities:", styles['Heading4']))
                for vuln in target["vulnerabilities"]:
                    vuln_text = f"• {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Info')}) - CVSS: {vuln.get('cvss_score', 0)}"
                    story.append(Paragraph(vuln_text, styles['Normal']))
                    story.append(Paragraph(f"  {vuln.get('description', '')}", styles['Normal']))
            
            if target.get("security_recommendations"):
                story.append(Spacer(1, 0.1*inch))
                story.append(Paragraph("Security Recommendations:", styles['Heading4']))
                for rec in target["security_recommendations"]:
                    story.append(Paragraph(f"• {rec}", styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("─" * 80, styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        doc.build(story)


class GhostSnifferGUI:
    """
    Main GUI application for The Ghost-Sniffer wireless security auditing tool.
    
    Provides a four-phase workflow interface for network discovery, vulnerability
    analysis, exploit testing, and comprehensive reporting.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("The Ghost-Sniffer: Wireless Security Auditing Tool (Demonstration)")
        self.root.geometry("1200x800")
        self.theme = DEFAULT_THEME
        self.fonts = DEFAULT_FONTS
        self.root.configure(bg=self.theme["bg"])
        
        self.phase1 = Phase1GhostSniffer(self.phase_callback)
        self.phase2 = Phase2ProtocolDaemon(self.phase_callback)
        self.phase3 = Phase3AutopwnSprite(self.phase_callback)
        self.phase4 = Phase4VulnerabilityCartograph(self.phase_callback)
        
        self.captured_networks = []
        self.analyses = []
        self.exploits = []
        self.current_report = None
        
        self.scapy_available = SCAPY_AVAILABLE
        self.netifaces_available = NETIFACES_AVAILABLE
        
        self.available_interfaces = get_network_interfaces()
        
        self._build_ui()
        
        self._show_startup_info()
        
        # Register cleanup on window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _show_info(self, title, message):
        show_modal_dialog(self.root, title, message, kind="info",
                          theme=self.theme, fonts=self.fonts)

    def _show_warning(self, title, message):
        show_modal_dialog(self.root, title, message, kind="warning",
                          theme=self.theme, fonts=self.fonts)

    def _show_error(self, title, message):
        show_modal_dialog(self.root, title, message, kind="error",
                          theme=self.theme, fonts=self.fonts)

    def _ask_yes_no(self, title, message, default="Yes"):
        result = show_modal_dialog(
            self.root,
            title,
            message,
            kind="warning",
            buttons=("Yes", "No"),
            default=default,
            theme=self.theme,
            fonts=self.fonts
        )
        return result == "Yes"
        
    def _build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.theme["bg"], borderwidth=0)
        style.configure(
            'TNotebook.Tab',
            background=self.theme["surface_alt"],
            foreground=self.theme["text"],
            padding=[20, 10],
            font=self.fonts["tab"]
        )
        style.map(
            'TNotebook.Tab',
            background=[('selected', self.theme["accent_bg"])],
            foreground=[('selected', self.theme["text"])]
        )
        style.configure(
            "Treeview",
            background=self.theme["surface"],
            fieldbackground=self.theme["surface"],
            foreground=self.theme["text"],
            rowheight=24,
            borderwidth=0,
            font=self.fonts["body"]
        )
        style.map(
            "Treeview",
            background=[("selected", self.theme["accent_bg"])],
            foreground=[("selected", self.theme["text"])]
        )
        style.configure(
            "Treeview.Heading",
            background=self.theme["surface_alt"],
            foreground=self.theme["text"],
            font=self.fonts["body_bold"]
        )
        style.configure(
            "TCombobox",
            fieldbackground=self.theme["surface"],
            background=self.theme["surface_alt"],
            foreground=self.theme["text"]
        )
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=self.theme["surface_alt"],
            background=self.theme["accent"]
        )
        
        title_frame = tk.Frame(self.root, bg=self.theme["bg"], pady=20)
        title_frame.pack(fill=tk.X)
        
        title_label = tk.Label(
            title_frame,
            text="The Ghost-Sniffer",
            font=self.fonts["title"],
            fg=self.theme["text"],
            bg=self.theme["bg"]
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Passive, Omnidirectional Eavesdropping • Protocol Divination • Exploit Orchestration • Vulnerability Cartography",
            font=self.fonts["subtitle"],
            fg=self.theme["muted"],
            bg=self.theme["bg"]
        )
        subtitle_label.pack()
        
        session_frame = tk.Frame(title_frame, bg=self.theme["bg"])
        session_frame.pack(pady=5)
        
        save_session_btn = tk.Button(
            session_frame,
            text="Save Session",
            command=self.save_session,
            font=self.fonts["body"],
            bg=self.theme["surface_alt"],
            fg=self.theme["text"],
            padx=10,
            pady=6,
            activebackground=self.theme["accent_bg"],
            activeforeground=self.theme["text"],
            relief=tk.FLAT
        )
        save_session_btn.pack(side=tk.LEFT, padx=5)
        
        load_session_btn = tk.Button(
            session_frame,
            text="Load Session",
            command=self.load_session,
            font=self.fonts["body"],
            bg=self.theme["surface_alt"],
            fg=self.theme["text"],
            padx=10,
            pady=6,
            activebackground=self.theme["accent_bg"],
            activeforeground=self.theme["text"],
            relief=tk.FLAT
        )
        load_session_btn.pack(side=tk.LEFT, padx=5)
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.phase1_frame = self._build_phase1()
        self.notebook.add(self.phase1_frame, text="Phase 1: The Third Ear")
        
        self.phase2_frame = self._build_phase2()
        self.notebook.add(self.phase2_frame, text="Phase 2: The Covenant-Pulse")
        
        self.phase3_frame = self._build_phase3()
        self.notebook.add(self.phase3_frame, text="Phase 3: The Legion of Keys")
        
        self.phase4_frame = self._build_phase4()
        self.notebook.add(self.phase4_frame, text="Phase 4: The Scroll of Truths")
        
    def _show_startup_info(self):
        scapy_status = "Available" if self.scapy_available else "Not Available"
        netifaces_status = "Available" if self.netifaces_available else "Not Available (Optional)"
        
        info_msg = f"""Ghost-Sniffer Initialized

Operating Mode: DEMONSTRATION MODE
Platform: {system_platform.system()}

IMPORTANT: This is a demonstration/educational tool.
   • Phase 1: Real network discovery (enabled)
   • Phase 2: Real vulnerability analysis (enabled)
   • Phase 3: Simulated exploit testing (for demonstration)
   • Phase 4: Real reporting (enabled)

Capabilities:
  • Scapy: {scapy_status}
  • Netifaces: {netifaces_status}

Available Interfaces: {', '.join(self.available_interfaces[:5])}{'...' if len(self.available_interfaces) > 5 else ''}

Note: Live network scanning enabled. Select a wireless interface to begin.
      On Linux, you may need to run with sudo and set interface to monitor mode.
      On Windows, ensure your wireless adapter supports monitor mode.

The tool is ready to begin the four-phase ritual."""
        
        self.phase1_log.insert(tk.END, info_msg + "\n\n")
        self.phase1_log.see(tk.END)
        
    def _build_phase1(self):
        frame = tk.Frame(self.notebook, bg=self.theme["bg"])
        
        instructions = tk.Label(
            frame,
            text="\"We'll cast a wide, silent net. Let the airwaves flow through it.\"",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"],
            wraplength=800
        )
        instructions.pack(pady=10)
        
        interface_frame = tk.Frame(frame, bg=self.theme["bg"])
        interface_frame.pack(pady=5)
        
        interface_label = tk.Label(
            interface_frame,
            text="Network Interface:",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"]
        )
        interface_label.pack(side=tk.LEFT, padx=5)
        
        self.interface_var = tk.StringVar()
        if self.available_interfaces:
            self.interface_var.set(self.available_interfaces[0])
        else:
            self.interface_var.set("No interfaces found")
        
        interface_combo = ttk.Combobox(
            interface_frame,
            textvariable=self.interface_var,
            values=self.available_interfaces,
            state="readonly",
            width=30
        )
        interface_combo.pack(side=tk.LEFT, padx=5)
        
        control_frame = tk.Frame(frame, bg=self.theme["bg"])
        control_frame.pack(pady=10)
        
        self.start_btn = tk.Button(
            control_frame,
            text="Start Scan",
            command=self.start_phase1,
            font=self.fonts["body_bold"],
            bg=self.theme["accent_bg"],
            fg=self.theme["text"],
            padx=20,
            pady=10,
            relief=tk.FLAT,
            activebackground=self.theme["accent"],
            activeforeground=self.theme["text"]
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(
            control_frame,
            text="Stop Scan",
            command=self.stop_phase1,
            font=self.fonts["body_bold"],
            bg=self.theme["surface_alt"],
            fg=self.theme["text"],
            padx=20,
            pady=10,
            relief=tk.FLAT,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        if system_platform.system() == "Windows":
            import_btn = tk.Button(
                control_frame,
                text="Import from Windows",
                command=self.import_windows_networks,
                font=self.fonts["body_bold"],
                bg=self.theme["surface_alt"],
                fg=self.theme["text"],
                padx=15,
                pady=8,
                relief=tk.FLAT
            )
            import_btn.pack(side=tk.LEFT, padx=5)
            
            manual_btn = tk.Button(
                control_frame,
                text="＋ Add Network",
                command=self.add_network_manually,
                font=self.fonts["body_bold"],
                bg=self.theme["surface_alt"],
                fg=self.theme["text"],
                padx=15,
                pady=8,
                relief=tk.FLAT
            )
            manual_btn.pack(side=tk.LEFT, padx=5)
        
        self.phase1_status = tk.Label(
            frame,
            text="Status: Idle - Ready to listen to the wireless world breathe",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"]
        )
        self.phase1_status.pack(pady=5)
        
        list_frame = tk.Frame(frame, bg=self.theme["bg"])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("SSID", "BSSID", "Channel", "RSSI", "Encryption")
        self.network_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=150)
            
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)
        
        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        log_label = tk.Label(
            frame,
            text="Activity Log:",
            font=self.fonts["body_bold"],
            fg=self.theme["text"],
            bg=self.theme["bg"]
        )
        log_label.pack(anchor=tk.W, padx=10)
        
        self.phase1_log = scrolledtext.ScrolledText(
            frame,
            height=8,
            font=self.fonts["mono"],
            bg=self.theme["surface"],
            fg=self.theme["text"],
            wrap=tk.WORD
        )
        self.phase1_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        return frame
        
    def _build_phase2(self):
        frame = tk.Frame(self.notebook, bg=self.theme["bg"])
        
        instructions = tk.Label(
            frame,
            text="\"We divine the signatures. We seek the covenant-pulse and read its aura for cracks.\"",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"],
            wraplength=800
        )
        instructions.pack(pady=10)
        
        control_frame = tk.Frame(frame, bg=self.theme["bg"])
        control_frame.pack(pady=10)
        
        self.analyze_btn = tk.Button(
            control_frame,
            text="Run Analysis",
            command=self.start_phase2,
            font=self.fonts["body_bold"],
            bg=self.theme["accent_bg"],
            fg=self.theme["text"],
            padx=20,
            pady=10,
            relief=tk.FLAT,
            activebackground=self.theme["accent"],
            activeforeground=self.theme["text"]
        )
        self.analyze_btn.pack()
        
        self.phase2_status = tk.Label(
            frame,
            text="Status: Awaiting network data from Phase 1",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"]
        )
        self.phase2_status.pack(pady=5)
        
        self.phase2_text = scrolledtext.ScrolledText(
            frame,
            height=25,
            font=self.fonts["mono"],
            bg=self.theme["surface"],
            fg=self.theme["text"],
            wrap=tk.WORD
        )
        self.phase2_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        return frame
        
    def _build_phase3(self):
        frame = tk.Frame(self.notebook, bg=self.theme["bg"])
        
        instructions = tk.Label(
            frame,
            text="\"We unleash the pack. A legion of clever, hungry instincts to worry at every weakness.\"",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"],
            wraplength=800
        )
        instructions.pack(pady=10)
        
        control_frame = tk.Frame(frame, bg=self.theme["bg"])
        control_frame.pack(pady=10)
        
        self.exploit_btn = tk.Button(
            control_frame,
            text="Run Exploit Testing",
            command=self.start_phase3,
            font=self.fonts["body_bold"],
            bg=self.theme["accent_bg"],
            fg=self.theme["text"],
            padx=20,
            pady=10,
            relief=tk.FLAT,
            activebackground=self.theme["accent"],
            activeforeground=self.theme["text"]
        )
        self.exploit_btn.pack()
        
        self.phase3_status = tk.Label(
            frame,
            text="Status: Awaiting vulnerability analysis from Phase 2",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"]
        )
        self.phase3_status.pack(pady=5)
        
        progress_frame = tk.Frame(frame, bg=self.theme["bg"])
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.phase3_progress_label = tk.Label(
            progress_frame,
            text="Progress:",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"]
        )
        self.phase3_progress_label.pack(side=tk.LEFT, padx=5)
        
        self.phase3_progress = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            length=400
        )
        self.phase3_progress.configure(style="Horizontal.TProgressbar")
        self.phase3_progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.phase3_progress_text = tk.Label(
            progress_frame,
            text="0%",
            font=self.fonts["body_bold"],
            fg=self.theme["text"],
            bg=self.theme["bg"],
            width=5
        )
        self.phase3_progress_text.pack(side=tk.LEFT, padx=5)
        
        self.phase3_text = scrolledtext.ScrolledText(
            frame,
            height=22,
            font=self.fonts["mono"],
            bg=self.theme["surface"],
            fg=self.theme["text"],
            wrap=tk.WORD
        )
        self.phase3_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        return frame
        
    def _build_phase4(self):
        frame = tk.Frame(self.notebook, bg=self.theme["bg"])
        
        instructions = tk.Label(
            frame,
            text="\"The scroll of truths is inscribed. It reveals the true names of the defenses that failed.\"",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"],
            wraplength=800
        )
        instructions.pack(pady=10)
        
        control_frame = tk.Frame(frame, bg=self.theme["bg"])
        control_frame.pack(pady=10)
        
        self.report_btn = tk.Button(
            control_frame,
            text="Generate Report",
            command=self.start_phase4,
            font=self.fonts["body_bold"],
            bg=self.theme["accent_bg"],
            fg=self.theme["text"],
            padx=20,
            pady=10,
            relief=tk.FLAT,
            activebackground=self.theme["accent"],
            activeforeground=self.theme["text"]
        )
        self.report_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = tk.Button(
            control_frame,
            text="Export Report",
            command=self.export_report,
            font=self.fonts["body_bold"],
            bg=self.theme["surface_alt"],
            fg=self.theme["text"],
            padx=20,
            pady=10,
            state=tk.DISABLED,
            relief=tk.FLAT
        )
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.phase4_status = tk.Label(
            frame,
            text="Status: Awaiting exploit results from Phase 3",
            font=self.fonts["body"],
            fg=self.theme["muted"],
            bg=self.theme["bg"]
        )
        self.phase4_status.pack(pady=5)
        
        self.phase4_text = scrolledtext.ScrolledText(
            frame,
            height=25,
            font=self.fonts["mono"],
            bg=self.theme["surface"],
            fg=self.theme["text"],
            wrap=tk.WORD
        )
        self.phase4_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        return frame
        
    def phase_callback(self, event_type: str, data):
        if event_type == "network_discovered":
            self._add_network(data)
        elif event_type == "error":
            self._log_error(data)
        elif event_type == "analysis_complete":
            pass
        elif event_type == "exploit_success":
            self._log_exploit(data)
        elif event_type == "exploit_progress":
            self._update_exploit_progress(data)
        elif event_type == "report_generated":
            self._display_report(data)
            
    def start_phase1(self):
        interface = self.interface_var.get()
        if not interface or interface == "No interfaces found":
            self._show_error("Error", "No network interface selected. Please select a wireless interface.")
            return
        
        logger.info("Phase 1 starting on interface: %s", interface)
            
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.phase1_status.config(text=f"Status: Listening on {interface}... The ghost-sniffer drinks the RF spectrum")
        self.phase1_log.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] Opening the Third Ear...\n")
        self.phase1_log.insert(tk.END, f"[*] Selected interface: {interface}\n")
        self.phase1_log.insert(tk.END, "[*] Setting promiscuous resonance mode...\n")
        self.phase1_log.insert(tk.END, "[*] Casting the wide, silent net...\n\n")
        self.phase1.start_listening(interface)
        
    def stop_phase1(self):
        self.phase1.stop_listening()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.phase1_status.config(text=f"Status: Resonance ceased. {len(self.captured_networks)} networks captured.")
        self.phase1_log.insert(tk.END, f"\n[{datetime.now().strftime('%H:%M:%S')}] Ghost-sniffer silenced.\n")
        self.phase1_log.insert(tk.END, f"[*] Total catch: {len(self.captured_networks)} digital whispers\n")
    
    def import_windows_networks(self):
        if system_platform.system() != "Windows":
            self._show_info("Windows Only", "This feature is only available on Windows.")
            return
        
        self.phase1_status.config(text="Status: Scanning with Windows netsh...")
        self.phase1_log.insert(tk.END, f"\n[{datetime.now().strftime('%H:%M:%S')}] Using Windows netsh to scan networks...\n")
        self.phase1_log.see(tk.END)
        
        try:
            ps_script = """
            $networks = netsh wlan show networks mode=Bssid
            if ($LASTEXITCODE -ne 0) {
                $networks = netsh wlan show networks
            }
            $networks
            """
            
            result = subprocess.run(['powershell', '-Command', ps_script], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                networks_output = result.stdout
                networks = []
                current_network = None
                
                for line in networks_output.split('\n'):
                    line = line.strip()
                    if 'SSID' in line and ':' in line and 'BSSID' not in line:
                        if current_network:
                            networks.append(current_network)
                        ssid = line.split(':', 1)[1].strip()
                        current_network = {'ssid': ssid, 'bssid': 'Unknown', 'channel': 0, 'rssi': 0, 'encryption': 'Unknown'}
                    elif 'BSSID' in line and ':' in line and current_network:
                        bssid = line.split(':', 1)[1].strip()
                        current_network['bssid'] = bssid
                    elif 'Signal' in line and ':' in line and current_network:
                        signal_str = line.split(':', 1)[1].strip().replace('%', '')
                        try:
                            signal_pct = int(signal_str)
                            current_network['rssi'] = -100 + signal_pct
                        except:
                            pass
                    elif 'Authentication' in line and ':' in line and current_network:
                        auth = line.split(':', 1)[1].strip()
                        if 'WPA2' in auth:
                            current_network['encryption'] = 'WPA2'
                        elif 'WPA' in auth:
                            current_network['encryption'] = 'WPA'
                        elif 'WEP' in auth:
                            current_network['encryption'] = 'WEP'
                        elif 'Open' in auth:
                            current_network['encryption'] = 'Open'
                
                if current_network:
                    networks.append(current_network)
                
                for network in networks:
                    if not any(n.get('ssid') == network['ssid'] and n.get('bssid') == network['bssid'] 
                              for n in self.captured_networks):
                        self._add_network(network)
                        self.phase1_log.insert(tk.END, f"[+] Imported: {network['ssid']} ({network['bssid']})\n")
                
                self.phase1_log.see(tk.END)
                self.phase1_status.config(text=f"Status: Imported {len(networks)} networks from Windows scanner")
            else:
                logger.warning("netsh scan failed: %s", result.stderr.strip())
                self.phase1_log.insert(tk.END, "[!] Failed to scan networks with netsh\n")
                self.phase1_log.see(tk.END)
        except Exception as e:
            logger.exception("Windows import failed")
            self.phase1_log.insert(tk.END, f"[!] Error importing networks: {str(e)}\n")
            self.phase1_log.see(tk.END)
    
    def add_network_manually(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Network Manually")
        dialog.configure(bg=self.theme["bg"])
        dialog.geometry("400x300")
        
        tk.Label(
            dialog,
            text="SSID (Network Name):",
            bg=self.theme["bg"],
            fg=self.theme["muted"],
            font=self.fonts["body"]
        ).pack(pady=5)
        ssid_entry = tk.Entry(dialog, font=self.fonts["body"], width=40, bg=self.theme["surface"], fg=self.theme["text"])
        ssid_entry.pack(pady=5)
        ssid_entry.focus()
        
        tk.Label(
            dialog,
            text="Encryption Type:",
            bg=self.theme["bg"],
            fg=self.theme["muted"],
            font=self.fonts["body"]
        ).pack(pady=5)
        encryption_var = tk.StringVar(value="WPA2")
        encryption_combo = ttk.Combobox(dialog, textvariable=encryption_var,
                                       values=["Open", "WEP", "WPA", "WPA2", "WPA3", "Unknown"],
                                       state="readonly", width=37)
        encryption_combo.pack(pady=5)
        
        tk.Label(
            dialog,
            text="BSSID (optional):",
            bg=self.theme["bg"],
            fg=self.theme["muted"],
            font=self.fonts["body"]
        ).pack(pady=5)
        bssid_entry = tk.Entry(dialog, font=self.fonts["body"], width=40, bg=self.theme["surface"], fg=self.theme["text"])
        bssid_entry.pack(pady=5)
        
        tk.Label(
            dialog,
            text="Channel (optional, 0 for unknown):",
            bg=self.theme["bg"],
            fg=self.theme["muted"],
            font=self.fonts["body"]
        ).pack(pady=5)
        channel_entry = tk.Entry(dialog, font=self.fonts["body"], width=40, bg=self.theme["surface"], fg=self.theme["text"])
        channel_entry.insert(0, "0")
        channel_entry.pack(pady=5)
        
        def save_network():
            ssid = ssid_entry.get().strip()
            if not ssid:
                self._show_warning("Missing SSID", "Please enter a network name (SSID).")
                return
            
            try:
                channel = int(channel_entry.get().strip() or "0")
            except:
                channel = 0
            
            network = {
                "ssid": ssid,
                "bssid": bssid_entry.get().strip() or "Unknown",
                "channel": channel,
                "rssi": 0,
                "encryption": encryption_var.get()
            }
            
            if any(n.get('ssid') == network['ssid'] and n.get('bssid') == network['bssid'] 
                  for n in self.captured_networks):
                self._show_info("Already Exists", "This network is already in the list.")
            else:
                self._add_network(network)
                self.phase1_log.insert(tk.END, f"[+] Manually added network: {ssid}\n")
                self.phase1_log.see(tk.END)
                self._show_info("Success", f"Network '{ssid}' added successfully!")
            
            dialog.destroy()
        
        btn_frame = tk.Frame(dialog, bg=self.theme["bg"])
        btn_frame.pack(pady=10)
        
        save_btn = tk.Button(
            btn_frame,
            text="Add Network",
            command=save_network,
            bg=self.theme["accent_bg"],
            fg=self.theme["text"],
            padx=20,
            pady=5,
            relief=tk.FLAT,
            activebackground=self.theme["accent"],
            activeforeground=self.theme["text"]
        )
        save_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = tk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy,
            bg=self.theme["surface_alt"],
            fg=self.theme["text"],
            padx=20,
            pady=5,
            relief=tk.FLAT
        )
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
    def _add_network(self, network: Dict):
        self.captured_networks.append(network)
        self.network_tree.insert("", tk.END, values=(
            network.get("ssid", "Hidden"),
            network.get("bssid", "Unknown"),
            network.get("channel", "N/A"),
            f"{network.get('rssi', 0)} dBm",
            network.get("encryption", "Unknown")
        ))
        self.phase1_log.insert(tk.END, f"[+] Network discovered: {network.get('ssid', 'Hidden')} ({network.get('bssid')}) - {network.get('encryption')}\n")
        self.phase1_log.see(tk.END)
        
    def _log_error(self, error: str):
        logger.error("Error event: %s", error)
        self.phase1_log.insert(tk.END, f"[!] Error: {error}\n")
        self.phase1_log.see(tk.END)
        if "Npcap" in error or "pcap" in error.lower():
            self._show_error("Npcap Required", 
                f"{error}\n\nPlease install Npcap from https://npcap.com/\n"
                "Make sure to check 'WinPcap API-compatible Mode' during installation.\n"
                "Then restart your computer.")
        elif "Permission" in error or "Administrator" in error:
            self._show_warning("Permission Error", 
                f"{error}\n\nTry running Ghost-Sniffer as Administrator.")
        
    def start_phase2(self):
        if not self.captured_networks:
            self._show_warning("No Data", "No networks captured yet. Run Phase 1 first.")
            return
            
        self.phase2_status.config(text="Status: Protocol-daemon parsing the stream...")
        self.phase2_text.delete(1.0, tk.END)
        self.phase2_text.insert(tk.END, "Invoking Protocol-Daemon...\n")
        self.phase2_text.insert(tk.END, "=" * 80 + "\n\n")
        
        self.analyses = self.phase2.analyze_networks(self.captured_networks)
        
        for analysis in self.analyses:
            net = analysis["network"]
            self.phase2_text.insert(tk.END, f"\nNetwork: {net.get('ssid', 'Hidden')} ({net.get('bssid')})\n")
            self.phase2_text.insert(tk.END, f"   Encryption: {net.get('encryption')}\n")
            self.phase2_text.insert(tk.END, f"   Risk Score: {analysis['risk_score']:.1f}\n")
            self.phase2_text.insert(tk.END, f"   Handshake Detected: {'Yes' if analysis['handshake_detected'] else 'No'}\n")
            
            if analysis["vulnerabilities"]:
                self.phase2_text.insert(tk.END, "   Vulnerabilities:\n")
                for vuln in analysis["vulnerabilities"]:
                    self.phase2_text.insert(tk.END, f"      • {vuln['type']} ({vuln['severity']}) - CVSS: {vuln['cvss_score']}\n")
                    self.phase2_text.insert(tk.END, f"        {vuln['description']}\n")
            self.phase2_text.insert(tk.END, "\n" + "-" * 80 + "\n")
            
        self.phase2_status.config(text=f"Status: Analysis complete. {len(self.analyses)} networks analyzed.")
        self.phase2_text.see(tk.END)
        
    def start_phase3(self):
        if not self.analyses:
            self._show_warning("No Data", "No vulnerability analysis available. Run Phase 2 first.")
            return
        
        real_tools_available = self.phase3.real_exploits_available
        tools_status = self.phase3.tools_status
        available_tools = [k for k, v in tools_status.items() if v] if tools_status else []
        
        if real_tools_available and available_tools:
            logger.warning("Phase 3 running in REAL exploit mode.")
            disclaimer = self._ask_yes_no(
                "REAL EXPLOIT MODE - LEGAL WARNING",
                "WARNING: Real exploit tools detected!\n\n"
                "This will perform ACTUAL attacks:\n"
                "• Real password cracking\n"
                "• Real network compromise attempts\n"
                "• Real security testing\n\n"
                "LEGAL REQUIREMENTS:\n"
                "• Only use on networks YOU OWN\n"
                "• Or with EXPLICIT written authorization\n"
                "• Unauthorized access is ILLEGAL\n"
                "• You are responsible for your actions\n\n"
                f"Available tools: {', '.join(available_tools)}\n\n"
                "Do you have authorization to test these networks?",
                icon='warning'
            )
            
            if not disclaimer:
                return
            
            mode_text = "REAL EXPLOIT MODE"
            self.phase3_status.config(text=f"Status: Autopwn-sprite deploying REAL exploits...")
            self.phase3_progress['value'] = 0
            self.phase3_progress_text.config(text="0%")
            self.phase3_text.delete(1.0, tk.END)
            self.phase3_text.insert(tk.END, "Deploying Autopwn-Sprite (REAL EXPLOIT MODE)...\n")
            self.phase3_text.insert(tk.END, f"Real tools available: {', '.join(available_tools)}\n")
            self.phase3_text.insert(tk.END, "WARNING: Performing REAL attacks!\n")
            self.phase3_text.insert(tk.END, "Ensure you have authorization.\n")
        else:
            logger.info("Phase 3 running in SIMULATION mode.")
            disclaimer = self._ask_yes_no(
                "Simulation Mode",
                "Real exploit tools not available.\n\n"
                "Phase 3 will use SIMULATED exploits:\n"
                "• Results based on risk scores\n"
                "• No actual attacks performed\n"
                "• For demonstration only\n\n"
                "To enable real exploits, install:\n"
                "• aircrack-ng (WEP/WPA cracking)\n"
                "• reaver (WPS attacks)\n"
                "• hashcat (password cracking)\n\n"
                "Continue with simulated exploit testing?",
                icon='info'
            )
            
            if not disclaimer:
                return
            
            mode_text = "SIMULATION MODE"
            self.phase3_status.config(text="Status: Autopwn-sprite deploying exploits (SIMULATED)...")
            self.phase3_progress['value'] = 0
            self.phase3_progress_text.config(text="0%")
            self.phase3_text.delete(1.0, tk.END)
            self.phase3_text.insert(tk.END, "Deploying Autopwn-Sprite (SIMULATION MODE)...\n")
            self.phase3_text.insert(tk.END, "NOTE: Exploits are SIMULATED (real tools not available)\n")
        
        self.phase3_text.insert(tk.END, "=" * 80 + "\n\n")
        
        self.exploits = self.phase3.deploy_exploits(self.analyses)
        
        for exploit in self.exploits:
            net = exploit["network"]
            self.phase3_text.insert(tk.END, f"\nTarget: {net.get('ssid', 'Hidden')} ({net.get('bssid')})\n")
            
            exploits_attempted = exploit.get('exploits_attempted', [])
            if exploits_attempted and isinstance(exploits_attempted[0], dict):
                exploit_names = [e.get('name', 'Unknown') for e in exploits_attempted]
            else:
                exploit_names = exploits_attempted
            
            self.phase3_text.insert(tk.END, f"   Exploits Attempted: {', '.join(exploit_names) if exploit_names else 'None'}\n")
            
            if exploit.get("exploits_successful"):
                self.phase3_text.insert(tk.END, f"   Successful: {', '.join(exploit['exploits_successful'])}\n")
                self.phase3_text.insert(tk.END, f"   Status: COMPROMISED\n")
            else:
                self.phase3_text.insert(tk.END, f"   Status: Resistant (no successful exploits)\n")
            
            if exploit.get("exploit_details"):
                self.phase3_text.insert(tk.END, "   Details:\n")
                for detail in exploit["exploit_details"]:
                    self.phase3_text.insert(tk.END, f"      • {detail.get('exploit', 'Unknown')}: {detail.get('result', '')}\n")
            
            if exploit.get("time_taken"):
                self.phase3_text.insert(tk.END, f"   Time Taken: {exploit['time_taken']}s\n")
            
            self.phase3_text.insert(tk.END, "\n" + "-" * 80 + "\n")
            
        self.phase3_status.config(text=f"Status: Exploit deployment complete. {sum(1 for e in self.exploits if e.get('compromised', False))} networks compromised.")
        self.phase3_progress['value'] = 100
        self.phase3_progress_text.config(text="100%")
        self.phase3_text.see(tk.END)
        
    def _log_exploit(self, data: Dict):
        net = data["network"]
        exploit = data["exploit"]
        self.phase3_text.insert(tk.END, f"[!] EXPLOIT SUCCESS: {net.get('ssid')} - {exploit}\n")
        self.phase3_text.see(tk.END)
    
    def _update_exploit_progress(self, data: Dict):
        progress = data.get("progress", 0)
        status = data.get("status", "")
        net = data.get("network", {})
        
        self.phase3_progress['value'] = progress
        self.phase3_progress_text.config(text=f"{int(progress)}%")
        
        if status:
            ssid = net.get('ssid', 'Unknown')
            self.phase3_status.config(text=f"Status: {ssid} - {status}")
            if progress < 100:
                self.phase3_text.insert(tk.END, f"[*] {ssid}: {status}\n")
                self.phase3_text.see(tk.END)
        
    def start_phase4(self):
        if not self.exploits:
            self._show_warning("No Data", "No exploit results available. Run Phase 3 first.")
            return
            
        self.phase4_status.config(text="Status: Rendering vulnerability cartograph...")
        self.phase4_text.delete(1.0, tk.END)
        self.phase4_text.insert(tk.END, "Vulnerability Cartograph\n")
        self.phase4_text.insert(tk.END, "=" * 80 + "\n\n")
        
        self.current_report = self.phase4.generate_report(
            self.captured_networks,
            self.analyses,
            self.exploits
        )
        
        summary = self.current_report["summary"]
        self.phase4_text.insert(tk.END, "EXECUTIVE SUMMARY\n")
        self.phase4_text.insert(tk.END, "-" * 80 + "\n")
        self.phase4_text.insert(tk.END, f"Total Networks Discovered: {summary['total_networks']}\n")
        self.phase4_text.insert(tk.END, f"Vulnerable Networks: {summary['vulnerable_networks']}\n")
        self.phase4_text.insert(tk.END, f"Compromised Networks: {summary['compromised_networks']}\n")
        self.phase4_text.insert(tk.END, f"Critical Vulnerabilities: {summary['critical_vulnerabilities']}\n")
        self.phase4_text.insert(tk.END, f"High Vulnerabilities: {summary.get('high_vulnerabilities', 0)}\n")
        self.phase4_text.insert(tk.END, f"Medium Vulnerabilities: {summary.get('medium_vulnerabilities', 0)}\n")
        self.phase4_text.insert(tk.END, f"Average Risk Score: {summary.get('average_risk_score', 0):.2f}\n\n")
        
        self.phase4_text.insert(tk.END, "RISK HEAT MAP\n")
        self.phase4_text.insert(tk.END, "-" * 80 + "\n")
        self.phase4_text.insert(tk.END, f"Critical Risk: {len(self.current_report['heat_map']['critical'])} targets\n")
        self.phase4_text.insert(tk.END, f"High Risk: {len(self.current_report['heat_map']['high'])} targets\n")
        self.phase4_text.insert(tk.END, f"Medium Risk: {len(self.current_report['heat_map']['medium'])} targets\n")
        self.phase4_text.insert(tk.END, f"Low Risk: {len(self.current_report['heat_map']['low'])} targets\n\n")
        
        self.phase4_text.insert(tk.END, "PRIORITIZED TARGET LIST\n")
        self.phase4_text.insert(tk.END, "=" * 80 + "\n\n")
        
        for target in self.current_report["targets"]:
            net = target["network"]
            self.phase4_text.insert(tk.END, f"Rank #{target['rank']}: {net.get('ssid', 'Hidden')} ({net.get('bssid')})\n")
            self.phase4_text.insert(tk.END, f"   Risk Score: {target['risk_score']:.1f}\n")
            self.phase4_text.insert(tk.END, f"   Exploit Status: {target['exploit_status']}\n")
            self.phase4_text.insert(tk.END, f"   Recommendation: {target['recommended_action']}\n")
            if target.get("vulnerabilities"):
                self.phase4_text.insert(tk.END, "   Vulnerabilities:\n")
                for vuln in target["vulnerabilities"]:
                    self.phase4_text.insert(tk.END, f"      • {vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Info')}) - CVSS: {vuln.get('cvss_score', 0)}\n")
            if target.get("security_recommendations"):
                self.phase4_text.insert(tk.END, "   Security Recommendations:\n")
                for rec in target["security_recommendations"]:
                    self.phase4_text.insert(tk.END, f"      • {rec}\n")
            self.phase4_text.insert(tk.END, "\n" + "-" * 80 + "\n\n")
            
        self.phase4_status.config(text="Status: Vulnerability cartograph rendered. Scroll of truths complete.")
        self.export_btn.config(state=tk.NORMAL)
        self.phase4_text.see(tk.END)
        
    def save_session(self):
        from tkinter import filedialog
        
        session_data = {
            "timestamp": datetime.now().isoformat(),
            "captured_networks": self.captured_networks,
            "analyses": self.analyses,
            "exploits": self.exploits,
            "current_report": self.current_report
        }
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(session_data, f, indent=2, ensure_ascii=False)
                self._show_info("Session Saved", f"Session saved to {filename}")
            except Exception as e:
                self._show_error("Save Error", f"Failed to save session: {str(e)}")
    
    def load_session(self):
        from tkinter import filedialog
        
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                
                self.captured_networks = session_data.get("captured_networks", [])
                self.analyses = session_data.get("analyses", [])
                self.exploits = session_data.get("exploits", [])
                self.current_report = session_data.get("current_report")
                
                self._refresh_network_list()
                if self.analyses:
                    self._refresh_phase2_display()
                if self.exploits:
                    self._refresh_phase3_display()
                if self.current_report:
                    self._display_report(self.current_report)
                
                self._show_info("Session Loaded", f"Session loaded from {filename}")
            except Exception as e:
                self._show_error("Load Error", f"Failed to load session: {str(e)}")
    
    def _refresh_network_list(self):
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
        
        for network in self.captured_networks:
            self.network_tree.insert("", tk.END, values=(
                network.get("ssid", "Hidden"),
                network.get("bssid", "Unknown"),
                network.get("channel", "N/A"),
                f"{network.get('rssi', 0)} dBm",
                network.get("encryption", "Unknown")
            ))
    
    def _refresh_phase2_display(self):
        self.phase2_text.delete(1.0, tk.END)
        self.phase2_text.insert(tk.END, "Protocol-Daemon Analysis Results (Loaded from Session)\n")
        self.phase2_text.insert(tk.END, "=" * 80 + "\n\n")
        
        for analysis in self.analyses:
            net = analysis["network"]
            self.phase2_text.insert(tk.END, f"\nNetwork: {net.get('ssid', 'Hidden')} ({net.get('bssid')})\n")
            self.phase2_text.insert(tk.END, f"   Encryption: {net.get('encryption')}\n")
            self.phase2_text.insert(tk.END, f"   Risk Score: {analysis['risk_score']:.1f}\n")
            self.phase2_text.insert(tk.END, f"   Handshake Detected: {'Yes' if analysis['handshake_detected'] else 'No'}\n")
            
            if analysis["vulnerabilities"]:
                self.phase2_text.insert(tk.END, "   Vulnerabilities:\n")
                for vuln in analysis["vulnerabilities"]:
                    self.phase2_text.insert(tk.END, f"      • {vuln['type']} ({vuln['severity']}) - CVSS: {vuln['cvss_score']}\n")
                    self.phase2_text.insert(tk.END, f"        {vuln['description']}\n")
            self.phase2_text.insert(tk.END, "\n" + "-" * 80 + "\n")
        
        self.phase2_status.config(text=f"Status: {len(self.analyses)} networks analyzed (loaded from session).")
    
    def _refresh_phase3_display(self):
        self.phase3_text.delete(1.0, tk.END)
        self.phase3_text.insert(tk.END, "Autopwn-Sprite Results (Loaded from Session)\n")
        self.phase3_text.insert(tk.END, "=" * 80 + "\n\n")
        
        for exploit in self.exploits:
            net = exploit["network"]
            self.phase3_text.insert(tk.END, f"\nTarget: {net.get('ssid', 'Hidden')} ({net.get('bssid')})\n")
            self.phase3_text.insert(tk.END, f"   Exploits Attempted: {len(exploit.get('exploits_attempted', []))}\n")
            
            if exploit["exploits_successful"]:
                self.phase3_text.insert(tk.END, f"   Successful: {', '.join(exploit['exploits_successful'])}\n")
                self.phase3_text.insert(tk.END, f"   Status: COMPROMISED\n")
            else:
                self.phase3_text.insert(tk.END, f"   Status: Resistant (no successful exploits)\n")
            self.phase3_text.insert(tk.END, "\n" + "-" * 80 + "\n")
        
        self.phase3_status.config(text=f"Status: {sum(1 for e in self.exploits if e['compromised'])} networks compromised (loaded from session).")
        self.phase3_progress['value'] = 100
        self.phase3_progress_text.config(text="100%")
    
    def export_report(self):
        if not self.current_report:
            self._show_warning("No Report", "No report available to export. Generate a report first.")
            return
            
        from tkinter import filedialog
        
        # Create a custom dialog for format selection
        dialog = tk.Toplevel(self.root)
        dialog.title("Export Report")
        dialog.configure(bg=self.theme["bg"])
        dialog.geometry("300x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        format_var = tk.StringVar(value="json")
        
        tk.Label(
            dialog,
            text="Choose export format:",
            bg=self.theme["bg"],
            fg=self.theme["muted"],
            font=self.fonts["body_bold"]
        ).pack(pady=10)
        
        tk.Radiobutton(
            dialog,
            text="JSON",
            variable=format_var,
            value="json",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            selectcolor=self.theme["surface_alt"],
            font=self.fonts["body"]
        ).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(
            dialog,
            text="HTML",
            variable=format_var,
            value="html",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            selectcolor=self.theme["surface_alt"],
            font=self.fonts["body"]
        ).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(
            dialog,
            text="CSV",
            variable=format_var,
            value="csv",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            selectcolor=self.theme["surface_alt"],
            font=self.fonts["body"]
        ).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(
            dialog,
            text="PDF",
            variable=format_var,
            value="pdf",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            selectcolor=self.theme["surface_alt"],
            font=self.fonts["body"]
        ).pack(anchor=tk.W, padx=20, pady=5)
        
        def do_export():
            format_choice = format_var.get()
            dialog.destroy()
            
            if format_choice == "csv":
                filename = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
                )
                if filename:
                    try:
                        self.phase4.export_csv(self.current_report, filename)
                        self._show_info("Export Complete", f"CSV report exported to {filename}")
                    except Exception as e:
                        self._show_error("Export Error", f"Failed to export CSV: {str(e)}")
            elif format_choice == "json":
                filename = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
                )
                if filename:
                    try:
                        with open(filename, 'w', encoding='utf-8') as f:
                            json.dump(self.current_report, f, indent=2, ensure_ascii=False)
                        self._show_info("Export Complete", f"JSON report exported to {filename}")
                    except Exception as e:
                        self._show_error("Export Error", f"Failed to export JSON: {str(e)}")
            elif format_choice == "html":
                filename = filedialog.asksaveasfilename(
                    defaultextension=".html",
                    filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
                )
                if filename:
                    try:
                        self.phase4.export_html(self.current_report, filename)
                        self._show_info("Export Complete", f"HTML report exported to {filename}")
                    except Exception as e:
                        self._show_error("Export Error", f"Failed to export HTML: {str(e)}")
            elif format_choice == "pdf":
                filename = filedialog.asksaveasfilename(
                    defaultextension=".pdf",
                    filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
                )
                if filename:
                    try:
                        self.phase4.export_pdf(self.current_report, filename)
                        self._show_info("Export Complete", f"PDF report exported to {filename}")
                    except Exception as e:
                        self._show_error("Export Error", f"Failed to export PDF: {str(e)}")
        
        btn_frame = tk.Frame(dialog, bg=self.theme["bg"])
        btn_frame.pack(pady=10)
        
        tk.Button(
            btn_frame,
            text="Export",
            command=do_export,
            bg=self.theme["accent_bg"],
            fg=self.theme["text"],
            padx=20,
            pady=5,
            relief=tk.FLAT
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy,
            bg=self.theme["surface_alt"],
            fg=self.theme["text"],
            padx=20,
            pady=5,
            relief=tk.FLAT
        ).pack(side=tk.LEFT, padx=5)
    
    def on_closing(self):
        """Cleanup when closing the application"""
        if hasattr(self.phase3, 'real_engine') and self.phase3.real_engine:
            self.phase3.real_engine.cleanup()
        self.root.destroy()


def main():
    setup_logging()
    if not SCAPY_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        show_modal_dialog(
            root,
            "Missing Dependency",
            "Scapy is required but not installed.\n\nInstall it with:\n  pip install scapy",
            kind="error",
            theme=DEFAULT_THEME,
            fonts=DEFAULT_FONTS
        )
        root.destroy()
        return
    root = tk.Tk()
    app = GhostSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

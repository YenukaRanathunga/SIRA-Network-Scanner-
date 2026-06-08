"""
NetScan Pro v8.0 — Advanced Network & Vulnerability Scanner
BSc Final Year Project — WIRESHARK-LEVEL EDITION
Built with Python + PyQt6

v8.0 NEW:
  • Complete UI redesign — professional dark theme with gradient accents
  • Sidebar navigation panel (icon + label style like modern security tools)
  • Animated scan progress with ETA counter
  • Glowing status indicator (pulsing dot — ONLINE/SCANNING/IDLE)
  • Card-style dashboard with live counters
  • Full Wireshark-level packet capture: dissector, hex dump, conversations
  • Real .pcap export (open directly in Wireshark)
  • Display filter bar with quick-filter buttons
  • Follow TCP Stream dialog
  • Protocol colorization rules
  • Conversation tracker with statistics
"""

import sys
import socket
import json
import time
import threading
import subprocess
import requests
import re
import ssl
import struct
import uuid
import platform
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict

import asyncio
import logging
import logging.handlers
from pathlib import Path

# ─────────────────────────────────────────────
#  FILE LOGGER SETUP
# ─────────────────────────────────────────────
_LOG_DIR = Path.home() / "NetScanPro_logs"
_LOG_DIR.mkdir(exist_ok=True)
_log_file = _LOG_DIR / f"netscanpro_{datetime.now().strftime('%Y%m%d')}.log"

file_logger = logging.getLogger("NetScanPro")
file_logger.setLevel(logging.DEBUG)
_fh = logging.handlers.RotatingFileHandler(
    _log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
file_logger.addHandler(_fh)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QSpinBox, QFrame, QSplitter, QStatusBar, QFileDialog,
    QMessageBox, QGroupBox, QComboBox, QCheckBox, QMenu, QToolBar,
    QDialog, QDialogButtonBox, QListWidget, QListWidgetItem, QAbstractItemView,
    QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QTextCursor, QAction


# ─────────────────────────────────────────────
#  THEME v8.0 — Professional Security Tool
# ─────────────────────────────────────────────
DARK_BG        = "#0a0e17"
PANEL_BG       = "#111827"
SIDEBAR_BG     = "#0d1321"
CARD_BG        = "#151f2e"
BORDER         = "#1e2d42"
BORDER_BRIGHT  = "#2a4060"
ACCENT         = "#00e5ff"
ACCENT2        = "#7c3aed"    # Purple accent
ACCENT_DIM     = "#004d66"
ACCENT_GLOW    = "#00e5ff33"
TEXT_PRIMARY   = "#e2e8f0"
TEXT_SECONDARY = "#64748b"
TEXT_MUTED     = "#374151"
CRITICAL       = "#ef4444"
HIGH           = "#f97316"
MEDIUM         = "#eab308"
LOW            = "#22c55e"
INFO           = "#3b82f6"
WARNING        = "#f59e0b"
ONLINE_CLR     = "#22c55e"
OFFLINE_CLR    = "#ef4444"
UNSTABLE_CLR   = "#f59e0b"
SUCCESS        = "#10b981"

STYLESHEET = f"""
/* ═══ GLOBAL ═══════════════════════════════════════════════════════ */
QMainWindow, QWidget {{
    background-color: {DARK_BG};
    color: {TEXT_PRIMARY};
    font-family: 'Segoe UI', 'SF Pro Display', 'Inter', 'Consolas', sans-serif;
    font-size: 13px;
}}

/* ═══ GROUP BOX ═════════════════════════════════════════════════════ */
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    margin-top: 14px;
    padding: 12px 10px 10px 10px;
    background-color: {PANEL_BG};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 8px;
    color: {ACCENT};
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    font-weight: 700;
    background-color: {PANEL_BG};
    border-radius: 3px;
}}

/* ═══ INPUTS ════════════════════════════════════════════════════════ */
QLineEdit, QSpinBox, QComboBox {{
    background-color: {DARK_BG};
    border: 1px solid {BORDER};
    border-radius: 7px;
    padding: 7px 12px;
    color: {TEXT_PRIMARY};
    font-size: 13px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
    border: 1px solid {ACCENT};
    background-color: #0d1a24;
}}
QLineEdit:hover, QSpinBox:hover, QComboBox:hover {{
    border: 1px solid {BORDER_BRIGHT};
}}
QTextEdit {{
    background-color: {DARK_BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
    color: {TEXT_PRIMARY};
    font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace;
    font-size: 12px;
    line-height: 1.5;
    padding: 8px;
    selection-background-color: {ACCENT_DIM};
}}
QTextEdit:focus {{
    border: 1px solid {ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox::down-arrow {{
    width: 10px;
    height: 10px;
}}
QComboBox QAbstractItemView {{
    background-color: {CARD_BG};
    border: 1px solid {BORDER_BRIGHT};
    border-radius: 6px;
    color: {TEXT_PRIMARY};
    selection-background-color: {ACCENT_DIM};
    padding: 4px;
}}

/* ═══ BUTTONS ═══════════════════════════════════════════════════════ */
QPushButton {{
    background-color: {CARD_BG};
    border: 1px solid {BORDER_BRIGHT};
    border-radius: 7px;
    padding: 7px 16px;
    color: {TEXT_PRIMARY};
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.3px;
}}
QPushButton:hover {{
    border: 1px solid {ACCENT};
    color: {ACCENT};
    background-color: #0d1a24;
}}
QPushButton:pressed {{
    background-color: {ACCENT_DIM};
    border: 1px solid {ACCENT};
}}
QPushButton:disabled {{
    color: {TEXT_MUTED};
    border-color: {TEXT_MUTED};
    background-color: {DARK_BG};
}}
QPushButton#scanBtn {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #004d66, stop:1 #006680);
    border: 1px solid {ACCENT};
    color: {ACCENT};
    font-size: 14px;
    font-weight: 700;
    padding: 11px 24px;
    letter-spacing: 2px;
    border-radius: 8px;
}}
QPushButton#scanBtn:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {ACCENT}, stop:1 #00b8cc);
    color: {DARK_BG};
    border: 1px solid {ACCENT};
}}
QPushButton#stopBtn {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #3d0f0f, stop:1 #4a1010);
    border: 1px solid {CRITICAL};
    color: {CRITICAL};
    font-weight: 700;
    border-radius: 8px;
}}
QPushButton#stopBtn:hover {{
    background: {CRITICAL};
    color: white;
}}
QPushButton#discoverBtn {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #0d2d0d, stop:1 #163616);
    border: 1px solid {LOW};
    color: {LOW};
    font-weight: 700;
    letter-spacing: 1px;
    border-radius: 8px;
}}
QPushButton#discoverBtn:hover {{
    background: {LOW};
    color: {DARK_BG};
}}
QPushButton#accentBtn {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #2d1a5e, stop:1 #3d2070);
    border: 1px solid {ACCENT2};
    color: #c4b5fd;
    font-weight: 600;
    border-radius: 7px;
}}
QPushButton#accentBtn:hover {{
    background: {ACCENT2};
    color: white;
}}

/* ═══ PROGRESS BAR ══════════════════════════════════════════════════ */
QProgressBar {{
    background-color: {DARK_BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    height: 10px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {ACCENT}, stop:0.5 #00b8cc, stop:1 {ACCENT2[:-2]}aa);
    border-radius: 5px;
}}

/* ═══ TABLES ════════════════════════════════════════════════════════ */
QTableWidget {{
    background-color: {DARK_BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: {BORDER};
    color: {TEXT_PRIMARY};
    font-size: 12px;
    alternate-background-color: #0d1520;
}}
QTableWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid {BORDER};
}}
QTableWidget::item:selected {{
    background-color: {ACCENT_DIM};
    color: {ACCENT};
}}
QHeaderView::section {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {CARD_BG}, stop:1 {DARK_BG});
    border: none;
    border-bottom: 2px solid {ACCENT};
    border-right: 1px solid {BORDER};
    padding: 9px 12px;
    color: {ACCENT};
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-weight: 700;
}}

/* ═══ TABS ══════════════════════════════════════════════════════════ */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    background-color: {PANEL_BG};
    top: -1px;
}}
QTabBar {{
    qproperty-usesScrollButtons: true;
}}
QTabBar::tab {{
    background-color: {DARK_BG};
    border: 1px solid {BORDER};
    border-bottom: none;
    border-radius: 7px 7px 0 0;
    padding: 9px 16px;
    color: {TEXT_SECONDARY};
    font-size: 12px;
    margin-right: 2px;
    font-weight: 600;
    min-width: 0px;
}}
QTabBar::tab:selected {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 {PANEL_BG}, stop:1 {PANEL_BG});
    color: {ACCENT};
    border-bottom: 2px solid {ACCENT};
}}
QTabBar::tab:hover:!selected {{
    color: {ACCENT};
    background-color: #0d1520;
}}
QTabBar::scroller {{ width: 24px; }}
QTabBar QToolButton {{
    background-color: {PANEL_BG};
    border: 1px solid {BORDER};
    color: {ACCENT};
    border-radius: 4px;
}}

/* ═══ SCROLLBARS ════════════════════════════════════════════════════ */
QScrollBar:vertical {{
    background: {DARK_BG};
    width: 8px;
    border-radius: 4px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER_BRIGHT};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {ACCENT_DIM}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {DARK_BG};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER_BRIGHT};
    border-radius: 4px;
}}
QScrollBar::handle:horizontal:hover {{ background: {ACCENT_DIM}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ═══ STATUS BAR ════════════════════════════════════════════════════ */
QStatusBar {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {SIDEBAR_BG}, stop:1 {DARK_BG});
    border-top: 1px solid {BORDER};
    color: {TEXT_SECONDARY};
    font-size: 11px;
    padding: 4px 10px;
}}

/* ═══ SPLITTER ══════════════════════════════════════════════════════ */
QSplitter::handle {{
    background-color: {BORDER};
    width: 2px;
    height: 2px;
    border-radius: 1px;
}}
QSplitter::handle:hover {{ background-color: {ACCENT}; }}

/* ═══ MISC ══════════════════════════════════════════════════════════ */
QToolTip {{
    background-color: {CARD_BG};
    color: {ACCENT};
    border: 1px solid {BORDER_BRIGHT};
    font-size: 11px;
    padding: 6px 10px;
    border-radius: 6px;
}}
QListWidget {{
    background-color: {DARK_BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
    color: {TEXT_PRIMARY};
    font-size: 12px;
    padding: 4px;
}}
QListWidget::item {{
    padding: 6px 10px;
    border-radius: 5px;
}}
QListWidget::item:selected {{
    background-color: {ACCENT_DIM};
    color: {ACCENT};
}}
QListWidget::item:hover {{
    background-color: {CARD_BG};
}}
QDialog {{
    background-color: {DARK_BG};
    color: {TEXT_PRIMARY};
    border-radius: 10px;
}}
QCheckBox {{
    color: {TEXT_PRIMARY};
    font-size: 12px;
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 2px solid {BORDER_BRIGHT};
    border-radius: 4px;
    background-color: {DARK_BG};
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}
QCheckBox::indicator:hover {{
    border-color: {ACCENT};
}}
QToolBar {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {SIDEBAR_BG}, stop:1 {DARK_BG});
    border-bottom: 1px solid {BORDER};
    padding: 4px 8px;
    spacing: 6px;
}}
QToolBar QToolButton {{
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 10px;
    color: {TEXT_SECONDARY};
    font-size: 12px;
    font-weight: 600;
}}
QToolBar QToolButton:hover {{
    background-color: {CARD_BG};
    border-color: {BORDER_BRIGHT};
    color: {ACCENT};
}}
"""

# ─────────────────────────────────────────────
#  MITIGATION DATABASE  (FIX: satisfies proposal requirement)
# ─────────────────────────────────────────────
MITIGATION_BY_SERVICE = {
    "SSH":         "Update OpenSSH to latest version. Disable password auth, use key-based auth. Restrict access via firewall.",
    "FTP":         "Replace FTP with SFTP or FTPS. Disable anonymous login. Apply latest vsftpd/ProFTPD patches.",
    "FTP-Data":    "Replace FTP with SFTP or FTPS. Disable anonymous login.",
    "Telnet":      "DISABLE Telnet immediately — traffic is unencrypted. Replace with SSH.",
    "SMTP":        "Update mail server software. Enable STARTTLS/TLS. Configure SPF, DKIM, DMARC.",
    "DNS":         "Update BIND/DNS server. Enable DNSSEC. Restrict zone transfers to authorised servers only.",
    "TFTP":        "Disable TFTP if not required. Restrict access via ACL. Use SFTP instead.",
    "HTTP":        "Enable HTTPS (redirect HTTP → HTTPS). Update web server (Apache/nginx/IIS). Apply WAF.",
    "HTTPS":       "Ensure TLS 1.2/1.3 only. Disable weak ciphers. Renew and monitor certificates.",
    "HTTPS-Alt":   "Ensure TLS 1.2/1.3 only. Disable weak ciphers. Renew and monitor certificates.",
    "POP3":        "Use POP3S (port 995). Disable plain POP3. Update mail client and server software.",
    "SFTP":        "Update SFTP server. Use key-based authentication. Restrict access via firewall.",
    "NetBIOS":     "Disable NetBIOS if not required. Block ports 137-139 at the firewall.",
    "IMAP":        "Use IMAPS (port 993). Update Dovecot/Courier. Enforce TLS connections.",
    "SMB":         "Apply all MS security patches (esp. EternalBlue). Disable SMBv1. Restrict to authorised hosts.",
    "SMTPS":       "Update mail server. Verify TLS configuration. Apply latest patches.",
    "Submission":  "Update mail server. Enforce authentication. Apply latest patches.",
    "IMAPS":       "Update IMAP server. Ensure strong TLS configuration.",
    "POP3S":       "Update POP3 server. Ensure strong TLS configuration.",
    "MSSQL":       "Apply latest SQL Server patches. Restrict network access. Disable SA account. Enable auditing.",
    "Oracle":      "Apply latest Oracle CPU patches. Restrict listener access. Audit privileged accounts.",
    "NFS":         "Restrict NFS exports to specific IPs. Use NFSv4 with Kerberos auth. Apply patches.",
    "HTTP-Dev":    "Do not expose dev servers publicly. Use reverse proxy with auth. Update framework.",
    "MySQL":       "Apply latest MySQL/MariaDB patches. Disable remote root login. Use strong passwords.",
    "RDP":         "Enable Network Level Authentication. Apply all Windows patches. Use VPN. Restrict access by IP.",
    "HTTP-Alt":    "Update web server. Restrict public access if development server. Apply WAF.",
    "PostgreSQL":  "Apply latest patches. Restrict pg_hba.conf. Use strong passwords. Enable SSL.",
    "VNC-HTTP":    "Use VNC only over VPN or SSH tunnel. Apply strong password. Update VNC server.",
    "VNC":         "Use VNC only over VPN or SSH tunnel. Apply strong password. Avoid public exposure.",
    "Redis":       "Bind Redis to localhost only. Set requirepass. Disable dangerous commands. Apply patches.",
    "Elasticsearch": "Do not expose publicly. Enable X-Pack security. Restrict with firewall.",
    "MongoDB":     "Enable authentication. Bind to localhost. Disable unauthenticated access. Apply patches.",
    "Unknown":     "Investigate this service. If not required, disable it. Apply firewall rules.",
}

MITIGATION_BY_SEVERITY = {
    "CRITICAL": "IMMEDIATE ACTION REQUIRED: Patch or disable this service. Isolate affected host if possible.",
    "HIGH":     "Patch within 24-72 hours. Review firewall rules. Monitor for active exploitation.",
    "MEDIUM":   "Patch within 30 days. Apply compensating controls (firewall, IDS). Review configurations.",
    "LOW":      "Patch in next maintenance window. Monitor for changes in exploitability.",
    "UNKNOWN":  "Review this vulnerability manually. Apply patches if available.",
}


def get_mitigation(service: str, severity: str) -> str:
    svc_fix = MITIGATION_BY_SERVICE.get(service, MITIGATION_BY_SERVICE["Unknown"])
    sev_fix = MITIGATION_BY_SEVERITY.get(severity.upper(), MITIGATION_BY_SEVERITY["UNKNOWN"])
    return f"{sev_fix}\n    Service-specific: {svc_fix}"




# ─────────────────────────────────────────────
#  HELPERS: MAC / ARP / PING
# ─────────────────────────────────────────────

def get_mac_from_arp(ip: str) -> str:
    """Get MAC address from ARP table after a ping."""
    try:
        # FIX: cross-platform ping to trigger ARP entry
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)

        if platform.system().lower() == "windows":
            out = subprocess.check_output(["arp", "-a", ip], timeout=5, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and ip in parts[0]:
                    mac = parts[1].replace("-", ":")
                    if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                        return mac.upper()
        else:
            out = subprocess.check_output(["arp", "-n", ip], timeout=5, text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                if m:
                    return m.group(0).upper()
    except Exception:
        pass

    # Fallback: read /proc/net/arp (Linux)
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                # FIX: flag 0x6 = complete/reachable ARP entry (was incorrectly 0x2)
                if len(parts) >= 4 and parts[0] == ip and parts[2] in ("0x2", "0x6"):
                    return parts[3].upper()
    except Exception:
        pass
    return "N/A"


def oui_vendor(mac: str) -> str:
    """Very lightweight OUI lookup (first 3 octets)."""
    OUI = {
        "00:50:56": "VMware", "00:0C:29": "VMware", "00:1C:42": "Parallels",
        "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
        "00:1A:2B": "Cisco", "00:1B:54": "Cisco", "00:1D:A2": "Cisco",
        "00:50:F2": "Microsoft", "00:15:5D": "Microsoft Hyper-V",
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1E:67": "HP", "3C:D9:2B": "HP", "98:4B:E1": "HP",
        "00:17:88": "Philips Hue", "EC:B5:FA": "Apple",
        "A4:C3:F0": "Apple", "00:1F:5B": "Apple",
        "FC:FB:FB": "Cisco-Linksys", "00:18:F8": "Cisco-Linksys",
        "00:23:14": "ASUS", "04:92:26": "ASUS",
        "18:31:BF": "D-Link", "00:1B:11": "D-Link",
        "00:19:E0": "Samsung", "00:12:FB": "Samsung",
    }
    prefix = mac[:8].upper()
    return OUI.get(prefix, "Unknown")


def ping_host(ip: str, timeout: float = 1.0) -> tuple[bool, float]:
    """Ping a host. Returns (alive, latency_ms). FIX: cross-platform command."""
    try:
        # FIX: build correct command per OS (-W is Linux-only, Windows uses -w in ms)
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
        t0 = time.time()
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=timeout + 2)
        latency = (time.time() - t0) * 1000
        return result.returncode == 0, round(latency, 1)
    except Exception:
        pass

    # FIX: socket fallback — use separate sockets per port to avoid state issues
    for port in [80, 443]:
        try:
            t0 = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True, round((time.time() - t0) * 1000, 1)
            s.close()
        except Exception:
            pass
    return False, 0.0


def generate_subnet_ips(base_ip: str, count: int = 254) -> list:
    """Generate IPs for a /24 subnet."""
    parts = base_ip.split(".")
    if len(parts) < 3:
        return []
    base = ".".join(parts[:3])
    return [f"{base}.{i}" for i in range(1, min(count + 1, 255))]


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())


def sev_color(severity: str) -> str:
    """FIX: correctly map all four severity levels (was missing MEDIUM and LOW)."""
    s = severity.upper()
    if s == "CRITICAL":
        return CRITICAL
    elif s == "HIGH":
        return HIGH
    elif s == "MEDIUM":
        return MEDIUM
    elif s == "LOW":
        return LOW
    else:
        return INFO


# ─────────────────────────────────────────────
#  PORT PROFILE SELECTOR DIALOG
# ─────────────────────────────────────────────
class PortSelectDialog(QDialog):
    PROFILES = {
        "Common (1–1024)": list(range(1, 1025)),
        "Web (80, 443, 8080, 8443, 3000, 5000)": [80, 443, 8080, 8443, 3000, 5000],
        "Database (1433, 3306, 5432, 6379, 27017, 1521)": [1433, 3306, 5432, 6379, 27017, 1521],
        "Remote Access (22, 23, 3389, 5900, 5800)": [22, 23, 3389, 5900, 5800],
        "Mail (25, 110, 143, 465, 587, 993, 995)": [25, 110, 143, 465, 587, 993, 995],
        "File Transfer (20, 21, 69, 115, 139, 445, 2049)": [20, 21, 69, 115, 139, 445, 2049],
        "All (1–65535)": list(range(1, 65536)),
    }

    def __init__(self, parent=None, current_ports_str="1-1000"):
        super().__init__(parent)
        self.setWindowTitle("Port Selection")
        self.setMinimumSize(500, 440)
        self.setStyleSheet(parent.styleSheet() if parent else "")
        self.selected_ports = []

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        profile_group = QGroupBox("QUICK PROFILES")
        pl = QVBoxLayout(profile_group)
        self.profile_list = QListWidget()
        self.profile_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        for name in self.PROFILES:
            item = QListWidgetItem(name)
            self.profile_list.addItem(item)
        self.profile_list.itemSelectionChanged.connect(self._on_profile_change)
        pl.addWidget(self.profile_list)
        layout.addWidget(profile_group)

        custom_group = QGroupBox("CUSTOM PORTS")
        cl = QVBoxLayout(custom_group)
        hint = QLabel("Enter ports separated by commas or use ranges (e.g. 22, 80, 443, 8000-9000)")
        hint.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        hint.setWordWrap(True)
        self.custom_input = QLineEdit()
        self.custom_input.setPlaceholderText("e.g.  22, 80, 443, 8080-8090, 3306")
        self.custom_input.setText(current_ports_str)
        self.custom_input.textChanged.connect(self._on_custom_change)
        cl.addWidget(hint)
        cl.addWidget(self.custom_input)
        layout.addWidget(custom_group)

        preview_group = QGroupBox("PREVIEW")
        prev_l = QVBoxLayout(preview_group)
        self.preview_label = QLabel("")
        self.preview_label.setStyleSheet(f"color: {ACCENT}; font-size: 12px;")
        self.preview_label.setWordWrap(True)
        prev_l.addWidget(self.preview_label)
        layout.addWidget(preview_group)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        self._parse_and_preview(current_ports_str)

    def _on_profile_change(self):
        ports = set()
        for item in self.profile_list.selectedItems():
            ports.update(self.PROFILES.get(item.text(), []))
        if ports:
            sorted_ports = sorted(ports)
            self.selected_ports = sorted_ports
            self._update_preview(sorted_ports)
            self.custom_input.blockSignals(True)
            self.custom_input.setText(self._ports_to_str(sorted_ports))
            self.custom_input.blockSignals(False)

    def _on_custom_change(self, text):
        self._parse_and_preview(text)

    def _parse_and_preview(self, text: str):
        ports = self._parse_ports(text)
        self.selected_ports = ports
        self._update_preview(ports)

    def _update_preview(self, ports: list):
        if not ports:
            self.preview_label.setText("⚠  No valid ports selected.")
        else:
            sample = ", ".join(str(p) for p in ports[:20])
            suffix = f"  … (+{len(ports) - 20} more)" if len(ports) > 20 else ""
            self.preview_label.setText(f"✓  {len(ports)} port(s) selected:  {sample}{suffix}")

    @staticmethod
    def _parse_ports(text: str) -> list:
        ports = set()
        for part in text.replace(" ", "").split(","):
            if not part:
                continue
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    for p in range(int(a), int(b) + 1):
                        if 1 <= p <= 65535:
                            ports.add(p)
                except ValueError:
                    pass
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    pass
        return sorted(ports)

    @staticmethod
    def _ports_to_str(ports: list) -> str:
        if not ports:
            return ""
        result = []
        start = end = ports[0]
        for p in ports[1:]:
            if p == end + 1:
                end = p
            else:
                result.append(str(start) if start == end else f"{start}-{end}")
                start = end = p
        result.append(str(start) if start == end else f"{start}-{end}")
        return ", ".join(result)

    def get_ports(self):
        return self.selected_ports

    def get_ports_display(self):
        return self.custom_input.text().strip()


# ─────────────────────────────────────────────
#  DEVICE DISCOVERY WORKER
# ─────────────────────────────────────────────
class DeviceDiscoveryWorker(QThread):
    device_found   = pyqtSignal(dict)
    device_updated = pyqtSignal(dict)
    log            = pyqtSignal(str, str)
    progress       = pyqtSignal(int)
    done           = pyqtSignal(list)

    def __init__(self, subnet_base: str, timeout: float = 1.0):
        super().__init__()
        self.subnet_base = subnet_base
        self.timeout     = timeout
        self._stop       = False
        self.devices     = []

    def stop(self):
        self._stop = True

    def run(self):
        ips = generate_subnet_ips(self.subnet_base)
        total = len(ips)
        self.log.emit(f"[*] Scanning {total} hosts on subnet {self.subnet_base}.0/24 …", "info")

        lock = threading.Lock()
        results = []

        def probe(ip, idx):
            if self._stop:
                return
            alive, latency = ping_host(ip, self.timeout)
            self.progress.emit(int((idx / total) * 100))
            if alive:
                mac = get_mac_from_arp(ip)
                vendor = oui_vendor(mac)
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ip
                status = "UNSTABLE" if latency > 500 else "ONLINE"
                device = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "latency_ms": latency,
                    "status": status,
                    "first_seen": datetime.now().strftime("%H:%M:%S"),
                    "last_seen": datetime.now().strftime("%H:%M:%S"),
                    "uptime_checks": 1,
                    "downtime_checks": 0,
                    "uptime_pct": 100.0,
                }
                with lock:
                    results.append(device)
                self.device_found.emit(device)
                self.log.emit(
                    f"[+] {ip:<16} | {mac:<20} | {vendor:<15} | {hostname[:30]:<32} | {latency:.0f}ms",
                    "success"
                )

        threads = []
        for idx, ip in enumerate(ips):
            t = threading.Thread(target=probe, args=(ip, idx + 1), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= 50:
                for t2 in threads:
                    t2.join(timeout=2)
                threads = []

        for t in threads:
            t.join(timeout=2)

        self.progress.emit(100)
        self.log.emit(f"[✓] Discovery complete. {len(results)} device(s) found.", "success")
        self.done.emit(results)


# ─────────────────────────────────────────────
#  UPTIME MONITOR WORKER
# ─────────────────────────────────────────────
class UptimeMonitorWorker(QThread):
    status_update = pyqtSignal(dict)
    log           = pyqtSignal(str, str)

    def __init__(self, devices: list, interval: float = 30.0):
        super().__init__()
        self.devices   = devices
        self.interval  = interval
        self._stop     = False
        self._counters = {}

    def stop(self):
        self._stop = True

    def update_devices(self, devices: list):
        self.devices = devices

    def run(self):
        while not self._stop:
            for dev in list(self.devices):
                if self._stop:
                    break
                ip = dev["ip"]
                if ip not in self._counters:
                    self._counters[ip] = {"up": 0, "total": 0}
                alive, latency = ping_host(ip, 1.0)
                self._counters[ip]["total"] += 1
                if alive:
                    self._counters[ip]["up"] += 1
                c = self._counters[ip]
                uptime_pct = (c["up"] / c["total"] * 100) if c["total"] > 0 else 0.0
                status = "ONLINE" if alive else "OFFLINE"
                if alive and latency > 500:
                    status = "UNSTABLE"
                self.status_update.emit({
                    "ip": ip,
                    "status": status,
                    "latency_ms": latency,
                    "last_seen": datetime.now().strftime("%H:%M:%S"),
                    "uptime_pct": round(uptime_pct, 1),
                    "checks": c["total"],
                })
            for _ in range(int(self.interval)):
                if self._stop:
                    return
                time.sleep(1)


# ─────────────────────────────────────────────
#  SCAN WORKER
# ─────────────────────────────────────────────
class ScanWorker(QThread):
    log              = pyqtSignal(str, str)
    progress         = pyqtSignal(int)
    port_found       = pyqtSignal(dict)
    vuln_found       = pyqtSignal(dict)
    service_detected = pyqtSignal(dict)
    scan_done        = pyqtSignal(dict)
    rate_update      = pyqtSignal(int, int, int)   # ports/sec, done, total

    def __init__(self, target, ports: list, timeout, scan_techniques):
        super().__init__()
        self.target          = target
        self.ports           = ports
        self.timeout         = timeout
        self.scan_techniques = scan_techniques
        self._stop           = False
        self.results         = {
            "target": target,
            "open_ports": [],
            "vulns": [],
            "services": {},
            "start_time": "",
            "end_time": "",
            "scan_duration": 0
        }

    def stop(self):
        self._stop = True

    COMMON_SERVICES = {
        20:    {"name": "FTP-Data",      "vuln_keywords": ["ftp"]},
        21:    {"name": "FTP",           "vuln_keywords": ["ftp", "vsftpd", "proftpd"]},
        22:    {"name": "SSH",           "vuln_keywords": ["ssh", "openssh"]},
        23:    {"name": "Telnet",        "vuln_keywords": ["telnet"]},
        25:    {"name": "SMTP",          "vuln_keywords": ["smtp", "sendmail", "postfix"]},
        53:    {"name": "DNS",           "vuln_keywords": ["bind", "dns"]},
        69:    {"name": "TFTP",          "vuln_keywords": ["tftp"]},
        80:    {"name": "HTTP",          "vuln_keywords": ["http", "apache", "nginx", "iis"]},
        110:   {"name": "POP3",          "vuln_keywords": ["pop3"]},
        115:   {"name": "SFTP",          "vuln_keywords": ["sftp"]},
        139:   {"name": "NetBIOS",       "vuln_keywords": ["netbios", "samba"]},
        143:   {"name": "IMAP",          "vuln_keywords": ["imap"]},
        443:   {"name": "HTTPS",         "vuln_keywords": ["https", "ssl", "tls", "openssl"]},
        445:   {"name": "SMB",           "vuln_keywords": ["smb", "samba"]},
        465:   {"name": "SMTPS",         "vuln_keywords": ["smtp", "ssl"]},
        587:   {"name": "Submission",    "vuln_keywords": ["smtp"]},
        993:   {"name": "IMAPS",         "vuln_keywords": ["imap", "ssl"]},
        995:   {"name": "POP3S",         "vuln_keywords": ["pop3", "ssl"]},
        1433:  {"name": "MSSQL",         "vuln_keywords": ["mssql", "sql server"]},
        1521:  {"name": "Oracle",        "vuln_keywords": ["oracle"]},
        2049:  {"name": "NFS",           "vuln_keywords": ["nfs"]},
        3000:  {"name": "HTTP-Dev",      "vuln_keywords": ["http"]},
        3306:  {"name": "MySQL",         "vuln_keywords": ["mysql", "mariadb"]},
        3389:  {"name": "RDP",           "vuln_keywords": ["rdp", "remote desktop"]},
        5000:  {"name": "HTTP-Alt",      "vuln_keywords": ["http"]},
        5432:  {"name": "PostgreSQL",    "vuln_keywords": ["postgresql"]},
        5800:  {"name": "VNC-HTTP",      "vuln_keywords": ["vnc"]},
        5900:  {"name": "VNC",           "vuln_keywords": ["vnc"]},
        6379:  {"name": "Redis",         "vuln_keywords": ["redis"]},
        8080:  {"name": "HTTP-Alt",      "vuln_keywords": ["http", "tomcat", "jenkins"]},
        8443:  {"name": "HTTPS-Alt",     "vuln_keywords": ["https", "ssl"]},
        8090:  {"name": "HTTP-Alt",      "vuln_keywords": ["http"]},
        9200:  {"name": "Elasticsearch", "vuln_keywords": ["elasticsearch"]},
        27017: {"name": "MongoDB",       "vuln_keywords": ["mongodb"]},
    }

    def extract_version(self, banner: str, service: str) -> str:
        patterns = [
            r"OpenSSH[_\s]+([\w\.]+)",
            r"Apache[\s/]+([\d\.]+)",
            r"nginx[\s/]+([\d\.]+)",
            r"vsftpd\s+([\d\.]+)",
            r"ProFTPD[\s]+([\d\.]+)",
            r"Postfix[\s]+([\d\.]+)",
            r"MySQL[\s]+([\d\.]+)",
            r"MariaDB[\s]+([\d\.]+)",
            r"Microsoft[\s\-]+IIS[\s/]+([\d\.]+)",
            r"SSH-([\d\.]+)",
            r"(\d+\.\d+[\.\d\w\-]*)",
        ]
        for pat in patterns:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                return m.group(1)
        return "N/A"

    def enhanced_grab_banner(self, ip, port):
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            probes = {
                21: b"USER anonymous\r\n",
                22: b"SSH-2.0-Client\r\n",
                25: b"EHLO test\r\n",
                80: b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
                443: b"HEAD / HTTP/1.0\r\n\r\n",
                3306: b"\x00\x00\x00\x01\x85\xa2\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
            }
            if port in probes:
                s.send(probes[port])
                time.sleep(0.5)
            banner = s.recv(1024).decode(errors='ignore').strip()
            if port == 443 and self.scan_techniques.get('ssl_check', True):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    ssl_sock = context.wrap_socket(s, server_hostname=ip)
                    cert = ssl_sock.getpeercert()
                    if cert:
                        banner += f" [SSL: {cert.get('issuer', '')}]"
                except Exception:
                    pass
            s.close()
            banner = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', banner)[:250]
        except socket.timeout:
            pass
        except Exception as e:
            banner = f"Error: {str(e)[:50]}"
        return banner

    def resolve_target(self):
        try:
            ip = socket.gethostbyname(self.target)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return ip, hostname
            except Exception:
                return ip, self.target
        except Exception:
            return None, None

    # ── CPE MAPPING ───────────────────────────
    CPE_MAP = {
        "SSH":           "cpe:2.3:a:openbsd:openssh",
        "HTTP":          "cpe:2.3:a:apache:http_server",
        "HTTPS":         "cpe:2.3:a:openssl:openssl",
        "FTP":           "cpe:2.3:a:proftpd:proftpd",
        "SMB":           "cpe:2.3:a:samba:samba",
        "MySQL":         "cpe:2.3:a:mysql:mysql",
        "PostgreSQL":    "cpe:2.3:a:postgresql:postgresql",
        "MongoDB":       "cpe:2.3:a:mongodb:mongodb",
        "Redis":         "cpe:2.3:a:redis:redis",
        "RDP":           "cpe:2.3:a:microsoft:remote_desktop_protocol",
        "Telnet":        "cpe:2.3:a:mit:kerberos",
        "SMTP":          "cpe:2.3:a:postfix:postfix",
        "DNS":           "cpe:2.3:a:isc:bind",
        "Elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
        "VNC":           "cpe:2.3:a:realvnc:vnc",
        "MSSQL":         "cpe:2.3:a:microsoft:sql_server",
    }

    # ── EXPLOIT-DB KNOWN EXPLOITS ─────────────
    EXPLOITDB = {
        "CVE-2017-0144": {"edb_id": "EDB-41987", "type": "Remote", "verified": True},
        "CVE-2020-0796": {"edb_id": "EDB-48537", "type": "Remote", "verified": True},
        "CVE-2019-0708": {"edb_id": "EDB-47416", "type": "Remote", "verified": True},
        "CVE-2021-41773": {"edb_id": "EDB-50383", "type": "WebApp", "verified": True},
        "CVE-2023-38408": {"edb_id": "EDB-51595", "type": "Remote", "verified": False},
        "CVE-2010-4221":  {"edb_id": "EDB-15449", "type": "Remote", "verified": True},
        "CVE-2021-44142": {"edb_id": "EDB-50564", "type": "Remote", "verified": True},
        "CVE-2020-10188": {"edb_id": "EDB-48170", "type": "Remote", "verified": True},
    }

    # ── OFFLINE CVE DATABASE (rich, versioned) ─
    LOCAL_CVES = {
        "smb":   [
            {"id": "CVE-2017-0144", "score": 9.3, "severity": "CRITICAL",
             "description": "EternalBlue: SMBv1 remote code execution in Windows. Used by WannaCry ransomware.",
             "published": "2017-03-14", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:microsoft:smb"},
            {"id": "CVE-2020-0796", "score": 10.0, "severity": "CRITICAL",
             "description": "SMBGhost: RCE via SMBv3 compression in Windows 10/Server 2019.",
             "published": "2020-03-12", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:microsoft:smb"},
        ],
        "samba": [
            {"id": "CVE-2021-44142", "score": 9.9, "severity": "CRITICAL",
             "description": "Samba heap R/W in vfs_fruit module. RCE as root. Affects < 4.13.17.",
             "published": "2022-01-31", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:samba:samba"},
            {"id": "CVE-2022-38023", "score": 8.1, "severity": "HIGH",
             "description": "Samba: Kerberos RC4-HMAC downgrade attack (Netlogon weak crypto).",
             "published": "2022-11-09", "exploitability": "2.2",
             "cpe": "cpe:2.3:a:samba:samba"},
        ],
        "ssh":   [
            {"id": "CVE-2023-38408", "score": 9.8, "severity": "CRITICAL",
             "description": "OpenSSH ssh-agent RCE via malicious PKCS#11 provider loading.",
             "published": "2023-07-19", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:openbsd:openssh"},
            {"id": "CVE-2024-6387",  "score": 8.1, "severity": "HIGH",
             "description": "regreSSHion: OpenSSH race condition RCE (glibc systems, < 9.8p1).",
             "published": "2024-07-01", "exploitability": "2.2",
             "cpe": "cpe:2.3:a:openbsd:openssh"},
        ],
        "openssh": [
            {"id": "CVE-2024-6387",  "score": 8.1, "severity": "HIGH",
             "description": "regreSSHion: OpenSSH race condition RCE (glibc systems, < 9.8p1).",
             "published": "2024-07-01", "exploitability": "2.2",
             "cpe": "cpe:2.3:a:openbsd:openssh"},
        ],
        "rdp":   [
            {"id": "CVE-2019-0708", "score": 9.8, "severity": "CRITICAL",
             "description": "BlueKeep: Pre-auth RCE via RDP on Windows 7/Server 2008.",
             "published": "2019-05-14", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:microsoft:remote_desktop_protocol"},
            {"id": "CVE-2020-0609", "score": 9.8, "severity": "CRITICAL",
             "description": "Windows RD Gateway pre-auth RCE via specially crafted requests.",
             "published": "2020-01-14", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:microsoft:remote_desktop_protocol"},
        ],
        "ftp":   [
            {"id": "CVE-2010-4221", "score": 10.0, "severity": "CRITICAL",
             "description": "ProFTPd RCE via TELNET_IAC escape sequence in mod_site_misc.",
             "published": "2010-11-09", "exploitability": "10.0",
             "cpe": "cpe:2.3:a:proftpd:proftpd"},
            {"id": "CVE-2015-3306", "score": 10.0, "severity": "CRITICAL",
             "description": "ProFTPD mod_copy unauthenticated file copy (SITE CPFR/CPTO).",
             "published": "2015-05-18", "exploitability": "10.0",
             "cpe": "cpe:2.3:a:proftpd:proftpd"},
        ],
        "vsftpd": [
            {"id": "CVE-2011-2523", "score": 10.0, "severity": "CRITICAL",
             "description": "vsftpd 2.3.4 backdoor — connects to port 6200 on :) in username.",
             "published": "2011-07-03", "exploitability": "10.0",
             "cpe": "cpe:2.3:a:beasts:vsftpd"},
        ],
        "http":  [
            {"id": "CVE-2021-41773", "score": 7.5, "severity": "HIGH",
             "description": "Apache 2.4.49 path traversal and mod_cgi RCE.",
             "published": "2021-10-04", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:apache:http_server"},
            {"id": "CVE-2022-31813", "score": 9.8, "severity": "CRITICAL",
             "description": "Apache mod_proxy: X-Forwarded-For header not sent to backend — auth bypass.",
             "published": "2022-06-08", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:apache:http_server"},
        ],
        "apache": [
            {"id": "CVE-2021-41773", "score": 7.5, "severity": "HIGH",
             "description": "Apache 2.4.49 path traversal + mod_cgi RCE.",
             "published": "2021-10-04", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:apache:http_server"},
        ],
        "nginx":  [
            {"id": "CVE-2021-23017", "score": 7.7, "severity": "HIGH",
             "description": "nginx DNS resolver 1-byte heap OOB write — potential RCE.",
             "published": "2021-06-01", "exploitability": "1.6",
             "cpe": "cpe:2.3:a:nginx:nginx"},
        ],
        "ssl":   [
            {"id": "CVE-2014-0160", "score": 7.5, "severity": "HIGH",
             "description": "Heartbleed: OpenSSL TLS heartbeat extension memory disclosure (64KB per request).",
             "published": "2014-04-07", "exploitability": "10.0",
             "cpe": "cpe:2.3:a:openssl:openssl"},
            {"id": "CVE-2022-0778", "score": 7.5, "severity": "HIGH",
             "description": "OpenSSL infinite loop in BN_mod_sqrt() — DoS via crafted certificate.",
             "published": "2022-03-15", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:openssl:openssl"},
        ],
        "telnet": [
            {"id": "CVE-2020-10188", "score": 9.8, "severity": "CRITICAL",
             "description": "Telnetd RCE via environment variable manipulation.",
             "published": "2020-03-06", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:gnu:inetutils"},
        ],
        "mysql": [
            {"id": "CVE-2023-21980", "score": 8.3, "severity": "HIGH",
             "description": "MySQL Server optimizer RCE via crafted SQL (requires auth).",
             "published": "2023-04-18", "exploitability": "1.2",
             "cpe": "cpe:2.3:a:mysql:mysql"},
        ],
        "redis": [
            {"id": "CVE-2022-0543", "score": 10.0, "severity": "CRITICAL",
             "description": "Redis Lua sandbox escape — RCE via crafted Lua script on Debian/Ubuntu.",
             "published": "2022-03-02", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:redis:redis"},
        ],
        "elasticsearch": [
            {"id": "CVE-2021-22145", "score": 6.5, "severity": "MEDIUM",
             "description": "Elasticsearch info disclosure — authenticated users can retrieve system info.",
             "published": "2021-07-21", "exploitability": "2.8",
             "cpe": "cpe:2.3:a:elastic:elasticsearch"},
        ],
        "bind": [
            {"id": "CVE-2023-50387", "score": 7.5, "severity": "HIGH",
             "description": "BIND KeyTrap: DNSSEC validation CPU exhaustion DoS (1 packet → hours of CPU).",
             "published": "2024-02-13", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:isc:bind"},
        ],
        "dns": [
            {"id": "CVE-2023-50387", "score": 7.5, "severity": "HIGH",
             "description": "BIND KeyTrap: DNSSEC CPU exhaustion DoS.",
             "published": "2024-02-13", "exploitability": "3.9",
             "cpe": "cpe:2.3:a:isc:bind"},
        ],
    }

    def query_nvd_enhanced(self, keyword, port):
        """
        Query NVD API with CPE-based lookup for accuracy.
        Falls back to rich offline CVE database on failure/rate-limit.
        Cross-references Exploit-DB for each CVE found.
        """
        import time as _time

        cves     = []
        kw_lower = keyword.lower()

        if kw_lower in ("unknown", "n/a", ""):
            return []

        # Get CPE string for this service (more accurate NVD results)
        service_name = self.COMMON_SERVICES.get(port, {}).get("name", keyword)
        cpe_str      = self.CPE_MAP.get(service_name, "")

        def _enrich_with_exploitdb(cve_list):
            """Add Exploit-DB data to any CVE that has a known exploit."""
            for cve in cve_list:
                edb = self.EXPLOITDB.get(cve["id"])
                if edb:
                    cve["exploit_available"] = True
                    cve["edb_id"]            = edb["edb_id"]
                    cve["exploit_type"]      = edb["type"]
                    cve["exploit_verified"]  = edb["verified"]
                    # Bump severity display if exploit is verified
                    if edb["verified"] and cve["severity"] in ("MEDIUM", "LOW"):
                        cve["severity"] = "HIGH"
                else:
                    cve["exploit_available"] = False
                    cve["edb_id"]            = ""
            return cve_list

        try:
            _time.sleep(0.6)
            url     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {'User-Agent': 'NetScanPro/8.0 Security Scanner'}

            # Try CPE-based query first (most accurate)
            if cpe_str:
                params = {"cpeName": cpe_str, "resultsPerPage": 8}
                r = requests.get(url, params=params, timeout=15, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("totalResults", 0) > 0:
                        cves = self._parse_nvd_response(data)
                        if cves:
                            self.log.emit(f"[✓] NVD CPE match: {len(cves)} CVE(s) for {service_name}", "success")
                            return _enrich_with_exploitdb(cves)

            # Fall back to keyword search
            params = {
                "keywordSearch":  keyword,
                "resultsPerPage": 10,
                "pubStartDate":   "2019-01-01T00:00:00.000"
            }
            r = requests.get(url, params=params, timeout=15, headers=headers)

            if r.status_code == 429:
                self.log.emit(f"[!] NVD rate limit — using offline CVE data for '{keyword}'", "warning")
                return _enrich_with_exploitdb(list(self.LOCAL_CVES.get(kw_lower, [])))
            elif r.status_code != 200:
                self.log.emit(f"[-] NVD HTTP {r.status_code} for '{keyword}' — using offline data", "error")
                return _enrich_with_exploitdb(list(self.LOCAL_CVES.get(kw_lower, [])))

            cves = self._parse_nvd_response(r.json())

            if not cves:
                self.log.emit(f"[*] NVD returned 0 results for '{keyword}' — using offline data", "warning")
                cves = list(self.LOCAL_CVES.get(kw_lower, []))

        except Exception as e:
            self.log.emit(f"[-] NVD query failed ({e}) — using offline CVE data", "error")
            cves = list(self.LOCAL_CVES.get(kw_lower, []))

        return _enrich_with_exploitdb(cves)

    @staticmethod
    def _parse_nvd_response(data: dict) -> list:
        """Parse NVD 2.0 API JSON into normalised CVE dicts."""
        cves = []
        for item in data.get("vulnerabilities", [])[:8]:
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description"
            )
            metrics      = cve.get("metrics", {})
            score        = 0.0
            severity     = "UNKNOWN"
            exploitability = "Unknown"
            for mt in ("cvssMetricV31", "cvssMetricV30"):
                if mt in metrics and metrics[mt]:
                    m    = metrics[mt][0]
                    cvss = m.get("cvssData", {})
                    score        = cvss.get("baseScore", 0.0)
                    severity     = cvss.get("baseSeverity", "UNKNOWN")
                    exploitability = str(m.get("exploitabilityScore", "Unknown"))
                    break
            if score == 0 and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                m    = metrics["cvssMetricV2"][0]
                cvss = m.get("cvssData", {})
                score    = cvss.get("baseScore", 0.0)
                severity = "MEDIUM" if score >= 5 else "LOW" if score > 0 else "UNKNOWN"
                exploitability = str(m.get("exploitabilityScore", "Unknown"))
            cves.append({
                "id":            cve_id,
                "score":         round(score, 1),
                "severity":      severity,
                "description":   desc[:250],
                "published":     cve.get("published", "Unknown"),
                "exploitability": exploitability,
            })
        return cves

    def run_port_scan(self, ip):
        """
        Async TCP scan (asyncio) + threaded UDP scan + SYN half-open (root) + OS fingerprinting.
        Falls back to connect-scan if SYN or asyncio are unavailable.
        """
        total = len(self.ports)
        open_count = 0
        self.log.emit(f"[*] Scanning {total} TCP port(s) on {ip} (async) …", "info")

        # ── Track timing for ports/sec signal ──
        self._scan_start_ts   = time.time()
        self._ports_done      = 0
        self._ports_open      = 0

        # ── Try SYN scan first (requires root/Administrator) ──
        syn_ports = self._try_syn_scan(ip)
        use_syn   = syn_ports is not None

        if use_syn:
            self.log.emit(f"[✓] SYN (half-open) scan active — stealth mode", "success")
            open_tcp_ports = syn_ports
            # Emit progress
            self.progress.emit(30)
        else:
            # Async connect-scan via asyncio
            open_tcp_ports = self._async_tcp_scan(ip)

        open_count = len(open_tcp_ports)

        # ── UDP scan (selected well-known UDP ports) ──
        if not self._stop:
            udp_results = self._udp_scan(ip)
            if udp_results:
                self.log.emit(f"[*] UDP: {len(udp_results)} open|filtered port(s)", "info")
            for port in udp_results:
                if self._stop:
                    break
                service_info = self.COMMON_SERVICES.get(port, {"name": "Unknown", "vuln_keywords": []})
                port_info = {
                    "port": port, "proto": "UDP",
                    "service": service_info["name"],
                    "banner": "", "version": "N/A",
                    "ip": ip, "state": "open|filtered",
                    "os_hint": ""
                }
                self.results["open_ports"].append(port_info)
                self.port_found.emit(port_info)
                self.log.emit(f"[+] Port {port}/udp OPEN|FILTERED — {service_info['name']}", "success")

        # ── Banner grab + OS fingerprint for open TCP ports ──
        self.log.emit(f"[*] Banner grabbing {open_count} open TCP port(s) …", "info")
        for i, port in enumerate(open_tcp_ports):
            if self._stop:
                break
            pct = 30 + int((i / max(open_count, 1)) * 40)
            self.progress.emit(pct)

            service_info = self.COMMON_SERVICES.get(port, {"name": "Unknown", "vuln_keywords": ["unknown"]})
            banner  = self.enhanced_grab_banner(ip, port)
            version = self.extract_version(banner, service_info["name"])

            # ── SSL/TLS deep check ──
            ssl_info = ""
            if self.scan_techniques.get('ssl_check', True) and port in (443, 8443, 993, 995, 465, 587, 636):
                ssl_info = self._check_ssl_tls(ip, port)

            # ── OS fingerprint (beyond TTL) ──
            os_hint = self._os_fingerprint(ip, port)

            port_info = {
                "port": port, "proto": "TCP",
                "service": service_info["name"],
                "banner": (banner + (" | " + ssl_info if ssl_info else ""))[:250],
                "version": version,
                "ip": ip,
                "state": "open",
                "os_hint": os_hint,
            }
            self.results["open_ports"].append(port_info)
            self.port_found.emit(port_info)

            self._ports_done += 1
            self._ports_open += 1
            elapsed = time.time() - self._scan_start_ts
            rate    = self._ports_done / elapsed if elapsed > 0 else 0
            self.rate_update.emit(int(rate), self._ports_done, total)

            critical_ports = [21, 22, 23, 445, 3389, 5900]
            if port in critical_ports:
                self.log.emit(f"[!] Port {port}/tcp OPEN — {service_info['name']} v{version}  ⚠ CRITICAL SERVICE", "warning")
            else:
                self.log.emit(f"[+] Port {port}/tcp OPEN — {service_info['name']} v{version}  {banner[:60]}", "success")

        return len(self.results["open_ports"])

    # ── ASYNC TCP CONNECT SCAN ────────────────
    def _async_tcp_scan(self, ip: str) -> list:
        """asyncio-based TCP connect scan — much faster than sequential sockets."""
        total  = len(self.ports)
        done   = [0]
        found  = []
        to     = self.timeout

        async def check_port(port):
            if self._stop:
                return
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=to
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                found.append(port)
            except Exception:
                pass
            finally:
                done[0] += 1
                pct = int((done[0] / total) * 30)
                self.progress.emit(pct)
                elapsed = time.time() - self._scan_start_ts
                rate    = done[0] / elapsed if elapsed > 0 else 0
                self.rate_update.emit(int(rate), done[0], total)

        async def run_all():
            sem = asyncio.Semaphore(500)  # 500 concurrent connections
            async def guarded(port):
                async with sem:
                    await check_port(port)
            await asyncio.gather(*[guarded(p) for p in self.ports])

        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(run_all())
            loop.close()
        except Exception as e:
            self.log.emit(f"[-] Async scan error: {e} — falling back to threaded scan", "warning")
            found = self._threaded_tcp_scan_fallback(ip)

        return sorted(found)

    def _threaded_tcp_scan_fallback(self, ip: str) -> list:
        """Thread-pool TCP scan — fallback if asyncio fails."""
        import concurrent.futures
        found = []
        lock  = threading.Lock()
        total = len(self.ports)
        done  = [0]

        def probe(port):
            if self._stop:
                return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        found.append(port)
                s.close()
            except Exception:
                pass
            finally:
                done[0] += 1
                self.progress.emit(int((done[0] / total) * 30))

        with concurrent.futures.ThreadPoolExecutor(max_workers=300) as ex:
            ex.map(probe, self.ports)
        return sorted(found)

    # ── SYN HALF-OPEN SCAN ────────────────────
    def _try_syn_scan(self, ip: str):
        """
        Attempt a raw SYN scan (requires root/Admin).
        Returns list of open ports on success, None if not permitted.
        """
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_sock.close()
        except PermissionError:
            return None
        except Exception:
            return None

        open_ports = []
        lock = threading.Lock()
        total = len(self.ports)
        done  = [0]

        def build_syn(src_port, dst_port, ip_dst):
            # Build minimal TCP SYN packet (IP + TCP headers)
            src_ip_bytes = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
            dst_ip_bytes = socket.inet_aton(ip_dst)

            # TCP header
            seq = 0
            ack = 0
            data_offset = 5 << 4
            flags = 0x02  # SYN
            window = socket.htons(65535)
            checksum = 0
            urg_ptr = 0
            tcp_hdr = struct.pack('!HHIIBBHHH',
                src_port, dst_port, seq, ack,
                data_offset, flags, window, checksum, urg_ptr)

            # Pseudo header for checksum
            placeholder = 0
            proto = socket.IPPROTO_TCP
            tcp_len = len(tcp_hdr)
            pseudo = struct.pack('!4s4sBBH', src_ip_bytes, dst_ip_bytes, placeholder, proto, tcp_len)

            def chksum(data):
                if len(data) % 2 != 0:
                    data += b'\x00'
                s = 0
                for i in range(0, len(data), 2):
                    s += (data[i] << 8) + data[i+1]
                s = (s >> 16) + (s & 0xffff)
                s += (s >> 16)
                return ~s & 0xffff

            cs = chksum(pseudo + tcp_hdr)
            tcp_hdr = struct.pack('!HHIIBBHHH',
                src_port, dst_port, seq, ack,
                data_offset, flags, window, cs, urg_ptr)
            return tcp_hdr

        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.settimeout(self.timeout)

            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)

            pending = set()

            def send_syns():
                base_src = 40000
                for i, port in enumerate(self.ports):
                    if self._stop:
                        break
                    src_port = base_src + (i % 10000)
                    pkt = build_syn(src_port, port, ip)
                    try:
                        send_sock.sendto(pkt, (ip, 0))
                    except Exception:
                        pass
                    with lock:
                        pending.add(port)
                    done[0] += 1
                    if done[0] % 500 == 0:
                        self.progress.emit(int((done[0] / total) * 25))

            send_thread = threading.Thread(target=send_syns, daemon=True)
            send_thread.start()

            deadline = time.time() + max(self.timeout * 2, 3)
            while time.time() < deadline and not self._stop:
                try:
                    raw, addr = recv_sock.recvfrom(65535)
                    if addr[0] != ip:
                        continue
                    if len(raw) < 40:
                        continue
                    # IP header length
                    ihl = (raw[0] & 0x0F) * 4
                    tcp = raw[ihl:]
                    if len(tcp) < 14:
                        continue
                    dst_port_r = struct.unpack('!H', tcp[0:2])[0]
                    flags_r    = tcp[13]
                    # SYN-ACK = 0x12
                    if (flags_r & 0x12) == 0x12:
                        with lock:
                            open_ports.append(dst_port_r)
                except socket.timeout:
                    break
                except Exception:
                    continue

            send_thread.join(timeout=2)
            recv_sock.close()
            send_sock.close()
        except Exception as e:
            self.log.emit(f"[-] SYN scan failed: {e}", "warning")
            return None

        return sorted(set(open_ports))

    # ── UDP SCAN ──────────────────────────────
    def _udp_scan(self, ip: str) -> list:
        """UDP scan for common service ports. Returns open|filtered ports."""
        UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1194, 4500, 5353]
        target_udp = [p for p in UDP_PORTS if p in self.ports or len(self.ports) > 1000]
        if not target_udp:
            return []

        open_filtered = []
        self.log.emit(f"[*] UDP probe on {len(target_udp)} common service ports …", "info")

        UDP_PROBES = {
            53:   b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
            123:  b"\x1b" + b"\x00" * 47,   # NTP
            161:  b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
        }

        for port in target_udp:
            if self._stop:
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(max(self.timeout, 1.5))
                probe = UDP_PROBES.get(port, b"\x00" * 8)
                s.sendto(probe, (ip, port))
                try:
                    data, _ = s.recvfrom(1024)
                    if data:
                        open_filtered.append(port)
                except socket.timeout:
                    # Timeout = no ICMP port unreachable received = open|filtered
                    open_filtered.append(port)
                except Exception:
                    pass
                s.close()
            except Exception:
                pass

        return open_filtered

    # ── SSL/TLS DEEP CHECK ────────────────────
    def _check_ssl_tls(self, ip: str, port: int) -> str:
        """Check SSL/TLS version, cipher, cert expiry, weak config."""
        issues = []
        try:
            # Try TLS 1.3
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    ver    = s.version()
                    cipher = s.cipher()
                    cert   = s.getpeercert()

                    # TLS version check
                    if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                        issues.append(f"WEAK TLS:{ver}")
                    else:
                        issues.append(f"TLS:{ver}")

                    # Cipher check
                    if cipher:
                        cipher_name = cipher[0]
                        if any(w in cipher_name.upper() for w in ("RC4", "DES", "NULL", "EXPORT", "ANON")):
                            issues.append(f"WEAK CIPHER:{cipher_name}")
                        else:
                            issues.append(f"Cipher:{cipher_name[:20]}")

                    # Cert expiry check
                    if cert:
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            try:
                                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_left = (exp - datetime.utcnow()).days
                                if days_left < 0:
                                    issues.append("CERT EXPIRED")
                                elif days_left < 30:
                                    issues.append(f"CERT EXPIRES IN {days_left}d")
                            except Exception:
                                pass
        except ssl.SSLError as e:
            issues.append(f"SSL ERR:{str(e)[:40]}")
        except Exception:
            pass

        return " | ".join(issues) if issues else ""

    # ── OS FINGERPRINT (beyond TTL) ───────────
    def _os_fingerprint(self, ip: str, port: int) -> str:
        """
        Multi-signal OS fingerprinting:
          1. TTL from TCP connection
          2. TCP window size
          3. Banner string hints
        Returns a best-guess OS string.
        """
        ttl        = 0
        window_sz  = 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            # TTL
            if hasattr(socket, 'IP_TTL'):
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            # Grab TCP window size via platform-specific socket option (Linux)
            try:
                import struct as _s
                info = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
                # TCP_INFO struct: rcv_mss at offset 44, snd_wnd at offset 76 (approx)
                window_sz = _s.unpack_from('I', info, 76)[0]
            except Exception:
                pass
            s.close()
        except Exception:
            pass

        # TTL-based guess
        if ttl >= 128:
            os_guess = "Windows"
        elif ttl >= 64:
            os_guess = "Linux/macOS"
        elif ttl >= 32:
            os_guess = "Older Windows/Device"
        elif ttl > 0:
            os_guess = "Network Device"
        else:
            os_guess = ""

        # Window size refinement
        if window_sz:
            if window_sz == 65535:
                os_guess = "Windows (Win10/Server)"
            elif window_sz == 29200:
                os_guess = "Linux (kernel 3.x+)"
            elif window_sz == 65535 and ttl == 64:
                os_guess = "macOS / FreeBSD"
            elif window_sz in (8192, 16384):
                os_guess = "Older Windows"

        return os_guess if os_guess else "Unknown"

    def run_service_detection(self):
        self.log.emit("[*] Performing service version detection …", "info")
        for port_info in self.results["open_ports"]:
            if self._stop:
                break
            self.service_detected.emit({
                "port": port_info["port"],
                "service": port_info["service"],
                "banner": port_info.get("banner", ""),
                "version": port_info.get("version", "N/A"),
                "security_issues": []
            })

    def run_vulnerability_scan(self):
        self.log.emit("[*] Starting vulnerability assessment …", "info")
        self.progress.emit(75)
        checked_services = set()
        all_vulns = []

        for port_info in self.results["open_ports"]:
            if self._stop:
                break
            service = port_info["service"]
            port = port_info["port"]
            service_data = self.COMMON_SERVICES.get(port, {})
            vuln_keywords = service_data.get("vuln_keywords", [service.lower()])
            service_key = service.lower()
            if service_key in checked_services:
                continue
            checked_services.add(service_key)
            self.log.emit(f"[*] Analyzing {service} (port {port}) …", "info")

            for keyword in vuln_keywords[:2]:
                if self._stop:
                    break
                cves = self.query_nvd_enhanced(keyword, port)
                for cve in cves:
                    cve["service"] = service
                    cve["port"] = port
                    # Add mitigation advice per CVE
                    cve["mitigation"] = get_mitigation(service, cve["severity"])
                    all_vulns.append(cve)
                    sev = cve["severity"].lower()
                    if sev == "critical":
                        self.log.emit(f"[🔥] {cve['id']}  Score:{cve['score']}  [CRITICAL]  {service}:{port}", "critical")
                    elif sev == "high":
                        self.log.emit(f"[⚠] {cve['id']}  Score:{cve['score']}  [HIGH]  {service}:{port}", "vuln")
                    else:
                        self.log.emit(f"[!] {cve['id']}  Score:{cve['score']}  [{cve['severity']}]  {service}:{port}", "vuln")

        unique_vulns = {}
        for v in all_vulns:
            cid = v["id"]
            if cid not in unique_vulns or unique_vulns[cid]["score"] < v["score"]:
                unique_vulns[cid] = v
        self.results["vulns"] = list(unique_vulns.values())
        # FIX: emit vuln_found for each unique CVE so the Vulnerabilities table populates
        for v in self.results["vulns"]:
            self.vuln_found.emit(v)
        return len(unique_vulns)

    def run(self):
        start_time = time.time()
        self.results["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log.emit(f"[*] Resolving target: {self.target}", "info")
        ip, hostname = self.resolve_target()
        if not ip:
            self.log.emit(f"[!] Could not resolve host: {self.target}", "error")
            self.scan_done.emit(self.results)
            return
        self.results["ip"] = ip
        self.results["hostname"] = hostname
        self.log.emit(f"[✓] Resolved to: {ip} ({hostname})", "success")

        open_count = self.run_port_scan(ip)
        self.log.emit(f"[*] Port scan done — {open_count} open port(s) found.", "info")

        if self.scan_techniques.get('service_detection', True):
            self.run_service_detection()

        vuln_count = 0
        if self.scan_techniques.get('vuln_scan', True) and open_count > 0:
            vuln_count = self.run_vulnerability_scan()
        else:
            self.progress.emit(100)

        self.progress.emit(100)
        self.results["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.results["scan_duration"] = round(time.time() - start_time, 2)
        self.log.emit(
            f"\n[✓] Scan complete!  Duration: {self.results['scan_duration']}s  |  "
            f"Ports: {open_count}  |  CVEs: {vuln_count}", "success"
        )

        critical_services = [p for p in self.results["open_ports"] if p["port"] in [21, 23, 445, 3389]]
        if critical_services:
            ports_list = ", ".join(str(p["port"]) for p in critical_services)
            self.log.emit(f"[⚠] Critical services on ports: {ports_list}", "warning")

        self.scan_done.emit(self.results)



# ─────────────────────────────────────────────
#  PACKET CAPTURE WORKER  (Wireshark-style)
# ─────────────────────────────────────────────
import struct as _struct

# ─────────────────────────────────────────────
#  WIRESHARK-LEVEL UPGRADE — v7.0
#  New modules: PCAP export, full dissector,
#  hex dump, display filter, TCP stream follow,
#  conversation tracker, protocol color rules
# ─────────────────────────────────────────────

import struct as _struct

# ── PORT SERVICE NAME DATABASE ───────────────
PORT_SERVICES = {
    20:"FTP-Data", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    53:"DNS", 67:"DHCP", 68:"DHCP", 69:"TFTP", 80:"HTTP",
    110:"POP3", 123:"NTP", 137:"NetBIOS-NS", 138:"NetBIOS-DGM",
    139:"NetBIOS-SSN", 143:"IMAP", 161:"SNMP", 162:"SNMP-Trap",
    179:"BGP", 194:"IRC", 389:"LDAP", 443:"HTTPS", 445:"SMB",
    465:"SMTPS", 514:"Syslog", 587:"Submission", 631:"IPP",
    636:"LDAPS", 993:"IMAPS", 995:"POP3S", 1080:"SOCKS",
    1433:"MSSQL", 1521:"Oracle", 1723:"PPTP", 2049:"NFS",
    3306:"MySQL", 3389:"RDP", 5060:"SIP", 5432:"PostgreSQL",
    5900:"VNC", 6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    9200:"Elasticsearch", 27017:"MongoDB",
}

def port_to_service(port: int) -> str:
    return PORT_SERVICES.get(port, f":{port}")

# ── PACKET COLORIZATION RULES ────────────────
def packet_row_color(pkt: dict) -> tuple:
    """Returns (fg_color, bg_color) for packet row — Wireshark-style."""
    proto  = pkt.get("proto", "")
    flags  = pkt.get("flags", "")
    dport  = pkt.get("dst_port", 0)
    sport  = pkt.get("src_port", 0)

    if "RST" in flags:
        return ("#ff4444", "#2a0a0a")   # Red — TCP Reset
    if proto == "ICMP":
        return ("#ffcc00", "#1a1600")   # Yellow — ICMP
    if "SYN" in flags and "ACK" not in flags:
        return ("#00cc66", "#001a0a")   # Green — TCP SYN
    if "FIN" in flags:
        return ("#ffaa00", "#1a0f00")   # Orange — TCP FIN
    if proto == "UDP":
        return ("#b0c4ff", "#0a0f1a")   # Light blue — UDP
    if dport in (80, 8080, 8443) or sport in (80, 8080):
        return ("#00d9ff", "#001a20")   # Cyan — HTTP
    if dport == 443 or sport == 443:
        return ("#88ff88", "#001a00")   # Light green — HTTPS
    if dport == 53 or sport == 53:
        return ("#ff88ff", "#1a001a")   # Purple — DNS
    if proto == "TCP":
        return ("#e6edf3", "#161b22")   # Default white — TCP
    return ("#8b949e", "#0d1117")       # Gray — other


# ── PROTOCOL DISSECTOR ───────────────────────
def dissect_packet(pkt: dict, raw_payload: bytes = b"") -> list:
    """Returns list of (layer_name, fields_dict) tuples for tree display."""
    layers = []

    # ── Ethernet (placeholder if we have it) ──
    layers.append(("Frame", {
        "Timestamp":    pkt.get("timestamp", ""),
        "Length":       f"{pkt.get('length', 0)} bytes on wire",
        "Protocol":     pkt.get("proto", "Unknown"),
    }))

    # ── IP Layer ──
    layers.append(("Internet Protocol (IP)", {
        "Source IP":        pkt.get("src_ip", ""),
        "Destination IP":   pkt.get("dst_ip", ""),
        "TTL":              str(pkt.get("ttl", "")),
        "OS Guess":         guess_os(pkt.get("ttl", 64)),
        "Total Length":     f"{pkt.get('length', 0)} bytes",
        "Protocol Number":  {"TCP":"6","UDP":"17","ICMP":"1"}.get(pkt.get("proto",""),"?"),
    }))

    proto = pkt.get("proto", "")

    # ── TCP Layer ──
    if proto == "TCP":
        layers.append(("Transmission Control Protocol (TCP)", {
            "Source Port":      f"{pkt.get('src_port','')} ({port_to_service(pkt.get('src_port',0))})",
            "Destination Port": f"{pkt.get('dst_port','')} ({port_to_service(pkt.get('dst_port',0))})",
            "Sequence Number":  str(pkt.get("seq", 0)),
            "Acknowledgment":   str(pkt.get("ack", 0)),
            "Flags":            f"[{pkt.get('flags','')}]",
            "Stream":           f"{min(pkt.get('src_port',0), pkt.get('dst_port',0))}",
        }))

    # ── UDP Layer ──
    elif proto == "UDP":
        layers.append(("User Datagram Protocol (UDP)", {
            "Source Port":      f"{pkt.get('src_port','')} ({port_to_service(pkt.get('src_port',0))})",
            "Destination Port": f"{pkt.get('dst_port','')} ({port_to_service(pkt.get('dst_port',0))})",
        }))

    # ── ICMP Layer ──
    elif proto == "ICMP":
        layers.append(("Internet Control Message Protocol (ICMP)", {
            "Note": "ICMP packet (ping/traceroute)",
        }))

    # ── Application Layer guesses ──
    dst_port = pkt.get("dst_port", 0)
    src_port = pkt.get("src_port", 0)
    hex_data = pkt.get("hex", "")

    if dst_port in (80, 8080) or src_port in (80, 8080):
        if hex_data:
            try:
                decoded = bytes.fromhex(hex_data).decode("utf-8", errors="replace")
                if decoded.startswith(("GET", "POST", "HTTP", "PUT", "DELETE", "HEAD")):
                    first_line = decoded.split("\r\n")[0]
                    layers.append(("HyperText Transfer Protocol (HTTP)", {
                        "Request/Response": first_line[:100],
                        "Payload bytes":    str(len(bytes.fromhex(hex_data))),
                    }))
            except Exception:
                pass

    if dst_port == 53 or src_port == 53:
        layers.append(("Domain Name System (DNS)", {
            "Note":       "DNS packet — use Wireshark for full decode",
            "Direction":  "Query" if dst_port == 53 else "Response",
        }))

    if dst_port in (20, 21) or src_port in (20, 21):
        layers.append(("File Transfer Protocol (FTP)", {
            "Port": str(dst_port or src_port),
            "Note": "FTP control channel — plaintext credentials possible",
        }))

    if dst_port == 22 or src_port == 22:
        layers.append(("Secure Shell (SSH)", {
            "Note": "Encrypted SSH session",
        }))

    return layers


def format_hex_dump(hex_str: str, bytes_per_row: int = 16) -> str:
    """Format hex string into hex+ASCII dump like Wireshark."""
    try:
        raw = bytes.fromhex(hex_str)
    except Exception:
        return hex_str

    lines = []
    for i in range(0, len(raw), bytes_per_row):
        chunk = raw[i:i + bytes_per_row]
        offset = f"{i:04x}"
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(bytes_per_row * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset}  {hex_part}  │  {ascii_part}")
    return "\n".join(lines)


# ── REAL PCAP FILE WRITER ────────────────────
class PcapWriter:
    """Write real libpcap format files (openable in Wireshark)."""
    MAGIC     = 0xa1b2c3d4
    VERSION_M = 2
    VERSION_m = 4
    SNAPLEN   = 65535
    LINKTYPE  = 1  # Ethernet

    def __init__(self, path: str):
        self.f = open(path, "wb")
        # Global header
        self.f.write(_struct.pack("<IHHiIII",
            self.MAGIC, self.VERSION_M, self.VERSION_m,
            0, 0, self.SNAPLEN, self.LINKTYPE))

    def write_packet(self, raw_bytes: bytes, ts: float = None):
        if ts is None:
            ts = time.time()
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        cap_len = min(len(raw_bytes), self.SNAPLEN)
        self.f.write(_struct.pack("<IIII", ts_sec, ts_usec, cap_len, len(raw_bytes)))
        self.f.write(raw_bytes[:cap_len])

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── CONVERSATION TRACKER ─────────────────────
class ConversationTracker:
    """Tracks unique IP-to-IP conversations with packet/byte counts."""
    def __init__(self):
        self._convs = {}   # key=(ip_a, ip_b) → dict

    def add_packet(self, pkt: dict):
        a = pkt.get("src_ip", "")
        b = pkt.get("dst_ip", "")
        key = tuple(sorted([a, b]))
        if key not in self._convs:
            self._convs[key] = {
                "ip_a": key[0], "ip_b": key[1],
                "packets": 0, "bytes": 0,
                "protos": set(), "ports": set(),
                "first": pkt.get("timestamp", ""),
                "last":  pkt.get("timestamp", ""),
            }
        c = self._convs[key]
        c["packets"] += 1
        c["bytes"]   += pkt.get("length", 0)
        c["protos"].add(pkt.get("proto", "?"))
        if pkt.get("dst_port"):
            c["ports"].add(pkt["dst_port"])
        c["last"] = pkt.get("timestamp", "")

    def get_all(self) -> list:
        result = []
        for c in self._convs.values():
            result.append({
                "ip_a":    c["ip_a"],
                "ip_b":    c["ip_b"],
                "packets": c["packets"],
                "bytes":   c["bytes"],
                "protos":  ", ".join(sorted(c["protos"])),
                "ports":   ", ".join(str(p) for p in sorted(c["ports"])[:5]),
                "first":   c["first"],
                "last":    c["last"],
            })
        return sorted(result, key=lambda x: -x["packets"])

    def clear(self):
        self._convs.clear()


PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
TCP_FLAGS = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH", 0x10: "ACK", 0x20: "URG"}


def decode_ip_packet(raw: bytes) -> dict:
    """Decode a raw IP packet into a structured dict."""
    try:
        if len(raw) < 20:
            return {}
        ver_ihl = raw[0]
        ihl = (ver_ihl & 0x0F) * 4
        proto_num = raw[9]
        proto = PROTO_MAP.get(proto_num, f"PROTO-{proto_num}")
        src_ip = socket.inet_ntoa(raw[12:16])
        dst_ip = socket.inet_ntoa(raw[16:20])
        ttl = raw[8]
        total_len = _struct.unpack("!H", raw[2:4])[0]
        payload = raw[ihl:]
        src_port = dst_port = 0
        flags_str = ""
        seq = ack = 0

        if proto_num == 6 and len(payload) >= 20:   # TCP
            src_port = _struct.unpack("!H", payload[0:2])[0]
            dst_port = _struct.unpack("!H", payload[2:4])[0]
            seq      = _struct.unpack("!I", payload[4:8])[0]
            ack      = _struct.unpack("!I", payload[8:12])[0]
            flags_raw = payload[13]
            flags_str = " ".join(n for bit, n in TCP_FLAGS.items() if flags_raw & bit)
        elif proto_num == 17 and len(payload) >= 8:  # UDP
            src_port = _struct.unpack("!H", payload[0:2])[0]
            dst_port = _struct.unpack("!H", payload[2:4])[0]

        app_data = payload[20:] if proto_num == 6 and len(payload) > 20 else payload[8:] if proto_num == 17 else payload
        hex_preview = app_data[:64].hex() if app_data else ""  # 64 bytes instead of 32

        return {
            "src_ip": src_ip, "dst_ip": dst_ip, "proto": proto,
            "src_port": src_port, "dst_port": dst_port,
            "ttl": ttl, "length": total_len,
            "flags": flags_str, "seq": seq, "ack": ack,
            "hex": hex_preview,
            "raw": raw.hex(),   # Store full raw for PCAP export
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "ts_float":  time.time(),
        }
    except Exception:
        return {}


def guess_os(ttl: int) -> str:
    """Estimate OS from TTL value."""
    if ttl >= 128:    return "Windows"
    elif ttl >= 64:   return "Linux / macOS"
    elif ttl >= 32:   return "Older Windows / Network Device"
    else:             return "Unknown"


class PacketCaptureWorker(QThread):
    packet_received = pyqtSignal(dict)
    log             = pyqtSignal(str, str)
    stats_update    = pyqtSignal(dict)

    def __init__(self, iface_ip: str = "", filter_proto: str = "ALL", bpf_host: str = "",
                 filter_port: int = 0, filter_flags: str = ""):
        super().__init__()
        self.iface_ip     = iface_ip
        self.filter_proto = filter_proto
        self.bpf_host     = bpf_host
        self.filter_port  = filter_port
        self.filter_flags = filter_flags
        self._stop        = False
        self._stats       = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0, "total": 0, "bytes": 0}

    def stop(self):
        self._stop = True

    def run(self):
        try:
            if platform.system().lower() == "windows":
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                host = self.iface_ip or socket.gethostbyname(socket.gethostname())
                sock.bind((host, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                import ctypes
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            sock.settimeout(1.0)
        except PermissionError:
            self.log.emit("[✗] Packet capture requires Administrator / root privileges. Run as Admin or sudo.", "error")
            return
        except Exception as e:
            self.log.emit(f"[✗] Packet capture init failed: {e}", "error")
            return

        self.log.emit("[✓] Packet capture started. Listening for packets…", "success")
        while not self._stop:
            try:
                raw, _ = sock.recvfrom(65535)
                data = raw[14:] if platform.system().lower() != "windows" else raw
                pkt = decode_ip_packet(data)
                if not pkt:
                    continue
                # ── Display filter logic ──
                fp = self.filter_proto
                if fp != "ALL" and pkt["proto"] != fp:
                    continue
                if self.bpf_host and self.bpf_host not in (pkt["src_ip"], pkt["dst_ip"]):
                    continue
                if self.filter_port and self.filter_port not in (pkt["src_port"], pkt["dst_port"]):
                    continue
                if self.filter_flags and self.filter_flags.upper() not in pkt["flags"].upper():
                    continue

                # Update stats
                proto = pkt["proto"]
                self._stats["total"] += 1
                self._stats["bytes"] += pkt["length"]
                if proto == "TCP":    self._stats["TCP"] += 1
                elif proto == "UDP":  self._stats["UDP"] += 1
                elif proto == "ICMP": self._stats["ICMP"] += 1
                else:                 self._stats["Other"] += 1
                self.packet_received.emit(pkt)
                if self._stats["total"] % 50 == 0:
                    self.stats_update.emit(dict(self._stats))
            except socket.timeout:
                continue
            except Exception:
                continue

        try:
            if platform.system().lower() == "windows":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
        except Exception:
            pass
        self.stats_update.emit(dict(self._stats))
        self.log.emit(f"[✓] Capture stopped. {self._stats['total']} packets  {self._stats['bytes']:,} bytes", "success")

class NetScanPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker           = None
        self.discovery_worker = None
        self.uptime_worker    = None
        self.capture_worker   = None
        self.captured_packets = []
        self.results          = {}
        self.scan_history     = []
        self.discovered_devices = []
        self.device_row_map   = {}
        self.settings         = QSettings("NetScanPro", "Settings")

        self.selected_ports    = list(range(1, 1001))
        self.ports_display_str = "1-1000"

        self.setWindowTitle("NetScan Pro v8.0 — Network & Vulnerability Scanner  |  Wireshark-level Capture")
        self.setMinimumSize(1600, 900)
        self.setStyleSheet(STYLESHEET)

        self._build_ui()
        self._load_settings()
        self._update_status("Ready. Enter a target and configure ports, then click Scan.")
        self._build_network_status()  # Show placeholder on startup

        self.auto_save_timer = QTimer()
        self.auto_save_timer.timeout.connect(self.auto_save_state)
        self.auto_save_timer.start(30000)

    # ──────────────────────────────────────────
    #  UI BUILD
    # ──────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top header bar ──
        root.addWidget(self._make_header())

        # ── Main body: sidebar + content ──
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._make_sidebar())
        body.addWidget(self._make_main_area(), 1)
        body_widget = QWidget()
        body_widget.setLayout(body)
        root.addWidget(body_widget, 1)

        self.setStatusBar(QStatusBar())
        self._create_toolbar()

    def _create_toolbar(self):
        tb = QToolBar("Quick Actions")
        tb.setMovable(False)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, tb)
        tb.setContentsMargins(8, 0, 8, 0)

        # Status indicator dot
        self.status_dot = QLabel("  ●  IDLE")
        self.status_dot.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600; padding: 0 10px;")
        tb.addWidget(self.status_dot)
        tb.addSeparator()

        for label, slot, tip in [
            ("🗑  Clear",       self.clear_logs,    "Clear all scan data"),
            ("📊  Export",      self.export_report, "Save report (JSON/HTML/TXT)"),
            ("❓  Help",        self.show_help,     "Show help"),
        ]:
            a = QAction(label, self)
            a.setToolTip(tip)
            a.triggered.connect(slot)
            tb.addAction(a)
            tb.addSeparator()

        tb.addWidget(QWidget())  # spacer

    def _make_header(self):
        """Sleek top header bar — like a real security dashboard."""
        w = QWidget()
        w.setFixedHeight(64)
        w.setStyleSheet(f"""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 {SIDEBAR_BG}, stop:0.4 #0d1a2a, stop:1 {DARK_BG});
            border-bottom: 2px solid {ACCENT};
        """)
        h = QHBoxLayout(w)
        h.setContentsMargins(20, 0, 20, 0)
        h.setSpacing(0)

        # Logo area
        logo_area = QHBoxLayout()
        logo_area.setSpacing(12)
        icon_lbl = QLabel("◈")
        icon_lbl.setStyleSheet(f"color:{ACCENT}; font-size:26px; font-weight:900;")
        title = QLabel("NetScan Pro")
        title.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 22px;
            font-weight: 700;
            letter-spacing: 1px;
        """)
        badge = QLabel("v8.0")
        badge.setStyleSheet(f"""
            background: {ACCENT_DIM};
            color: {ACCENT};
            font-size: 10px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 10px;
            margin-left: 4px;
            border: 1px solid {ACCENT};
        """)
        logo_area.addWidget(icon_lbl)
        logo_area.addWidget(title)
        logo_area.addWidget(badge)
        h.addLayout(logo_area)

        h.addSpacing(28)
        sep = QLabel("|")
        sep.setStyleSheet(f"color: {BORDER_BRIGHT}; font-size: 18px;")
        h.addWidget(sep)
        h.addSpacing(20)

        subtitle = QLabel("Advanced Network & Vulnerability Scanner  ·  Wireshark-level Capture")
        subtitle.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; letter-spacing: 0.3px;")
        h.addWidget(subtitle)

        h.addStretch()

        # Live stats capsules
        self.hdr_ports_lbl  = self._make_stat_capsule("OPEN PORTS", "—")
        self.hdr_vulns_lbl  = self._make_stat_capsule("CVEs", "—")
        self.hdr_devs_lbl   = self._make_stat_capsule("DEVICES", "—")
        for cap in [self.hdr_ports_lbl, self.hdr_vulns_lbl, self.hdr_devs_lbl]:
            h.addWidget(cap)
            h.addSpacing(8)

        h.addSpacing(12)
        sep2 = QLabel("|")
        sep2.setStyleSheet(f"color: {BORDER_BRIGHT}; font-size: 18px;")
        h.addWidget(sep2)
        h.addSpacing(12)

        # Clock
        self.clock_label = QLabel()
        self.clock_label.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 13px;
            font-weight: 600;
            font-family: 'Consolas', monospace;
            padding: 0 8px;
        """)
        h.addWidget(self.clock_label)

        timer = QTimer(self)
        timer.timeout.connect(self._tick_clock)
        timer.start(1000)
        self._tick_clock()
        return w

    def _make_stat_capsule(self, label_text: str, value_text: str) -> QWidget:
        """Stat capsule widget for header bar."""
        cap = QWidget()
        cap.setStyleSheet(f"""
            background-color: {CARD_BG};
            border: 1px solid {BORDER_BRIGHT};
            border-radius: 8px;
            padding: 2px 6px;
        """)
        lay = QVBoxLayout(cap)
        lay.setContentsMargins(10, 4, 10, 4)
        lay.setSpacing(0)
        lbl = QLabel(label_text)
        lbl.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:9px; font-weight:700; letter-spacing:1px;")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        val = QLabel(value_text)
        val.setStyleSheet(f"color:{ACCENT}; font-size:16px; font-weight:700; font-family:'Consolas',monospace;")
        val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(lbl)
        lay.addWidget(val)
        # Store value label for updating
        cap._val_label = val
        return cap

    def _update_header_stats(self):
        """Update the live stat capsules in the header."""
        ports = len(self.results.get("open_ports", []))
        vulns = len(self.results.get("vulns", []))
        devs  = len(self.discovered_devices)
        self.hdr_ports_lbl._val_label.setText(str(ports) if ports else "—")
        self.hdr_vulns_lbl._val_label.setText(str(vulns) if vulns else "—")
        self.hdr_devs_lbl._val_label.setText(str(devs) if devs else "—")
        # Color code vulns
        if vulns > 0:
            crit = sum(1 for v in self.results.get("vulns",[]) if v["severity"].upper() == "CRITICAL")
            clr = CRITICAL if crit > 0 else HIGH
            self.hdr_vulns_lbl._val_label.setStyleSheet(f"color:{clr}; font-size:16px; font-weight:700; font-family:'Consolas',monospace;")
        else:
            self.hdr_vulns_lbl._val_label.setStyleSheet(f"color:{ACCENT}; font-size:16px; font-weight:700; font-family:'Consolas',monospace;")

    def _tick_clock(self):
        self.clock_label.setText(datetime.now().strftime("  %Y-%m-%d   %H:%M:%S"))

    def _make_sidebar(self):
        """Left sidebar with scan controls — clean card design."""
        # Outer container with fixed width
        outer = QWidget()
        outer.setFixedWidth(300)
        outer.setStyleSheet(f"""
            QWidget {{
                background-color: {SIDEBAR_BG};
                border-right: 1px solid {BORDER};
            }}
        """)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Scrollable inner area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: transparent; }}
            QScrollBar:vertical {{ background:{DARK_BG}; width:6px; border-radius:3px; }}
            QScrollBar::handle:vertical {{ background:{BORDER_BRIGHT}; border-radius:3px; min-height:20px; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
        """)

        sidebar = QWidget()
        sidebar.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)

        # ── Target Card ──
        tg = QGroupBox("🎯  TARGET")
        tg.setStyleSheet(f"QGroupBox {{ background:{CARD_BG}; border-radius:10px; border:1px solid {BORDER_BRIGHT}; }} QGroupBox::title {{ color:{ACCENT}; background:{CARD_BG}; }}")
        tl = QVBoxLayout(tg)
        tl.setSpacing(8)
        tl.setContentsMargins(10, 14, 10, 10)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP · hostname · range (e.g. 192.168.1.1)")
        self.target_input.setMinimumHeight(36)
        self.target_input.setStyleSheet(f"""
            QLineEdit {{
                background:{DARK_BG}; border:1px solid {BORDER_BRIGHT};
                border-radius:7px; padding:7px 12px; color:{TEXT_PRIMARY};
                font-size:13px;
            }}
            QLineEdit:focus {{ border:1px solid {ACCENT}; background:#0a1520; }}
        """)
        tl.addWidget(self.target_input)

        qb = QHBoxLayout()
        qb.setSpacing(6)
        for label, slot in [
            ("localhost",  lambda: self.target_input.setText("localhost")),
            ("Local Net",  self.detect_local_network),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(28)
            btn.setStyleSheet(f"QPushButton {{ background:{DARK_BG}; border:1px solid {BORDER_BRIGHT}; border-radius:6px; color:{TEXT_SECONDARY}; font-size:11px; padding:0 10px; }} QPushButton:hover {{ border-color:{ACCENT}; color:{ACCENT}; }}")
            btn.clicked.connect(slot)
            qb.addWidget(btn)
        qb.addStretch()
        tl.addLayout(qb)
        lay.addWidget(tg)

        # ── Port Card ──
        pg = QGroupBox("🔌  PORTS")
        pg.setStyleSheet(f"QGroupBox {{ background:{CARD_BG}; border-radius:10px; border:1px solid {BORDER_BRIGHT}; }} QGroupBox::title {{ color:{ACCENT}; background:{CARD_BG}; }}")
        pl = QVBoxLayout(pg)
        pl.setSpacing(8)
        pl.setContentsMargins(10, 14, 10, 10)

        port_info_row = QHBoxLayout()
        self.ports_label = QLabel("1-1000")
        self.ports_label.setStyleSheet(f"color:{ACCENT}; font-size:12px; font-weight:700; font-family:'Consolas',monospace;")
        self.port_count_label = QLabel("1000 ports")
        self.port_count_label.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11px;")
        self.port_count_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        port_info_row.addWidget(self.ports_label, 1)
        port_info_row.addWidget(self.port_count_label)
        pl.addLayout(port_info_row)

        cfg_btn = QPushButton("⚙  Configure Ports …")
        cfg_btn.setMinimumHeight(32)
        cfg_btn.clicked.connect(self.open_port_selector)
        pl.addWidget(cfg_btn)

        presets = QHBoxLayout()
        presets.setSpacing(5)
        for lbl, ps in [
            ("Top 100", "21,22,23,25,53,80,110,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"),
            ("Web",     "80,443,3000,5000,8080,8443,8090"),
            ("All",     "1-65535"),
            ("DB",      "1433,1521,3306,5432,6379,27017,9200"),
        ]:
            b = QPushButton(lbl)
            b.setFixedHeight(26)
            b.setStyleSheet(f"QPushButton {{ background:{DARK_BG}; border:1px solid {BORDER_BRIGHT}; border-radius:5px; color:{TEXT_SECONDARY}; font-size:10px; padding:0 6px; }} QPushButton:hover {{ border-color:{ACCENT}; color:{ACCENT}; }}")
            b.clicked.connect(lambda _, p=ps: self._quick_set_ports(p))
            presets.addWidget(b)
        pl.addLayout(presets)
        lay.addWidget(pg)

        # ── Scan Config Card ──
        sg = QGroupBox("⚙  SCAN OPTIONS")
        sg.setStyleSheet(f"QGroupBox {{ background:{CARD_BG}; border-radius:10px; border:1px solid {BORDER_BRIGHT}; }} QGroupBox::title {{ color:{ACCENT}; background:{CARD_BG}; }}")
        sl = QVBoxLayout(sg)
        sl.setSpacing(8)
        sl.setContentsMargins(10, 14, 10, 10)

        tol = QHBoxLayout()
        tol_lbl = QLabel("Timeout:")
        tol_lbl.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:12px;")
        self.timeout_box = QComboBox()
        self.timeout_box.addItems(["0.3s", "0.5s", "1.0s", "2.0s", "3.0s"])
        self.timeout_box.setCurrentIndex(2)
        self.timeout_box.setFixedWidth(75)
        tol.addWidget(tol_lbl)
        tol.addStretch()
        tol.addWidget(self.timeout_box)
        sl.addLayout(tol)

        cb_style = f"QCheckBox {{ color:{TEXT_PRIMARY}; font-size:12px; spacing:8px; }} QCheckBox::indicator {{ width:15px; height:15px; border:2px solid {BORDER_BRIGHT}; border-radius:4px; background:{DARK_BG}; }} QCheckBox::indicator:checked {{ background:{ACCENT}; border-color:{ACCENT}; }}"
        self.service_check = QCheckBox("Service & Version Detection")
        self.service_check.setChecked(True)
        self.service_check.setStyleSheet(cb_style)
        self.vuln_check = QCheckBox("Vulnerability Scan (CVE / NVD)")
        self.vuln_check.setChecked(True)
        self.vuln_check.setStyleSheet(cb_style)
        self.ssl_check = QCheckBox("SSL / TLS Certificate Check")
        self.ssl_check.setChecked(True)
        self.ssl_check.setStyleSheet(cb_style)
        for cb in [self.service_check, self.vuln_check, self.ssl_check]:
            sl.addWidget(cb)
        lay.addWidget(sg)

        # ── Scan Controls Card ──
        sc = QGroupBox("▶  SCAN CONTROLS")
        sc.setStyleSheet(f"QGroupBox {{ background:{CARD_BG}; border-radius:10px; border:1px solid {ACCENT_DIM}; }} QGroupBox::title {{ color:{ACCENT}; background:{CARD_BG}; }}")
        scl = QVBoxLayout(sc)
        scl.setSpacing(6)
        scl.setContentsMargins(10, 16, 10, 10)

        self.scan_btn = QPushButton("▶   START SCAN")
        self.scan_btn.setObjectName("scanBtn")
        self.scan_btn.setMinimumHeight(42)
        self.scan_btn.clicked.connect(self.start_scan)
        scl.addWidget(self.scan_btn)

        row2 = QHBoxLayout()
        row2.setSpacing(6)
        self.stop_btn = QPushButton("■  STOP")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setFixedHeight(32)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("💾  EXPORT")
        self.export_btn.setFixedHeight(32)
        self.export_btn.clicked.connect(self.export_report)
        self.export_btn.setEnabled(False)
        row2.addWidget(self.stop_btn)
        row2.addWidget(self.export_btn)
        scl.addLayout(row2)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        scl.addSpacing(2)
        scl.addWidget(self.progress)

        prog_row = QHBoxLayout()
        self.pct_label = QLabel("IDLE")
        self.pct_label.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11px; font-family:'Consolas',monospace;")
        self.eta_label = QLabel("")
        self.eta_label.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11px;")
        self.eta_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        prog_row.addWidget(self.pct_label)
        prog_row.addWidget(self.eta_label)
        scl.addLayout(prog_row)
        lay.addWidget(sc)

        # ── Network Discovery Card ──
        dg = QGroupBox("🌐  NETWORK DISCOVERY")
        dg.setStyleSheet(f"QGroupBox {{ background:{CARD_BG}; border-radius:10px; border:1px solid {BORDER_BRIGHT}; }} QGroupBox::title {{ color:{ACCENT}; background:{CARD_BG}; }}")
        dl = QVBoxLayout(dg)
        dl.setSpacing(6)
        dl.setContentsMargins(10, 16, 10, 10)

        sub_row = QHBoxLayout()
        sub_row.setSpacing(6)
        sub_lbl = QLabel("Subnet:")
        sub_lbl.setStyleSheet(f"color:{TEXT_SECONDARY}; font-size:11px;")
        sub_lbl.setFixedWidth(48)
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("192.168.1")
        self.subnet_input.setFixedHeight(30)
        sub_row.addWidget(sub_lbl)
        sub_row.addWidget(self.subnet_input)
        dl.addLayout(sub_row)

        disc_row = QHBoxLayout()
        disc_row.setSpacing(6)
        self.discover_btn = QPushButton("🔍  DISCOVER HOSTS")
        self.discover_btn.setObjectName("discoverBtn")
        self.discover_btn.setFixedHeight(32)
        self.discover_btn.clicked.connect(self.start_discovery)
        self.stop_discover_btn = QPushButton("■ STOP")
        self.stop_discover_btn.setObjectName("stopBtn")
        self.stop_discover_btn.setFixedHeight(32)
        self.stop_discover_btn.clicked.connect(self.stop_discovery)
        self.stop_discover_btn.setEnabled(False)
        disc_row.addWidget(self.discover_btn, 2)
        disc_row.addWidget(self.stop_discover_btn, 1)
        dl.addLayout(disc_row)

        self.monitor_btn = QPushButton("📡  START UPTIME MONITOR")
        self.monitor_btn.setFixedHeight(30)
        self.monitor_btn.setObjectName("accentBtn")
        self.monitor_btn.clicked.connect(self.toggle_uptime_monitor)
        dl.addWidget(self.monitor_btn)
        lay.addWidget(dg)

        lay.addStretch()

        scroll.setWidget(sidebar)
        outer_layout.addWidget(scroll)
        return outer

    def _make_control_panel(self):
        """Thin compatibility wrapper — not used in v8 (sidebar replaces it)."""
        return self._make_sidebar()

    def _make_main_area(self):
        """Right content area with tabs + log."""
        panel = QWidget()
        panel.setStyleSheet(f"background:{DARK_BG};")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 10, 12, 8)
        layout.setSpacing(8)

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(False)
        self.tabs.setMovable(False)
        self.tabs.setDocumentMode(False)
        self.tabs.setElideMode(Qt.TextElideMode.ElideNone)
        self.tabs.setUsesScrollButtons(True)
        layout.addWidget(self.tabs, 1)


        self.port_table = QTableWidget(0, 7)
        self.port_table.setHorizontalHeaderLabels(["PORT", "SERVICE", "VERSION", "STATUS", "BANNER", "RISK", "OS HINT"])
        self.port_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.port_table.setColumnWidth(0, 75)
        self.port_table.setColumnWidth(1, 110)
        self.port_table.setColumnWidth(2, 100)
        self.port_table.setColumnWidth(3, 75)
        self.port_table.setColumnWidth(5, 90)
        self.port_table.setAlternatingRowColors(True)
        self.port_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.port_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.port_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.port_table.customContextMenuRequested.connect(self._port_table_context_menu)
        self.port_table.setSortingEnabled(True)
        self.tabs.addTab(self.port_table, "🔌 Ports")

        self.vuln_table = QTableWidget(0, 8)
        self.vuln_table.setHorizontalHeaderLabels(["CVE ID", "SERVICE", "PORT", "SCORE", "SEVERITY", "PUBLISHED", "EXPLOITABILITY", "EXPLOIT-DB"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col, w in [(1, 100), (2, 70), (3, 80), (4, 100), (5, 120), (6, 110), (7, 110)]:
            self.vuln_table.setColumnWidth(col, w)
        self.vuln_table.setAlternatingRowColors(True)
        self.vuln_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.vuln_table.itemClicked.connect(self.show_vuln_detail)
        self.vuln_table.setSortingEnabled(True)
        self.tabs.addTab(self.vuln_table, "🔒 Vulns")

        self.device_table = QTableWidget(0, 8)
        self.device_table.setHorizontalHeaderLabels([
            "IP ADDRESS", "MAC ADDRESS", "VENDOR", "HOSTNAME",
            "STATUS", "LATENCY", "UPTIME %", "LAST SEEN"
        ])
        self.device_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for col, w in [(0, 130), (1, 155), (3, 200), (4, 90), (5, 80), (6, 80), (7, 90)]:
            self.device_table.setColumnWidth(col, w)
        self.device_table.setAlternatingRowColors(True)
        self.device_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.device_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.device_table.itemDoubleClicked.connect(self.scan_selected_device)

        # Wrap in stacked widget: index 0 = placeholder, index 1 = table
        from PyQt6.QtWidgets import QStackedWidget
        self.device_stack = QStackedWidget()
        self.device_placeholder = QTextEdit()
        self.device_placeholder.setReadOnly(True)
        ph = self.device_placeholder
        ph.setTextColor(QColor(TEXT_SECONDARY))
        ph.append("\n\n  No network discovery data yet.")
        ph.setTextColor(QColor(ACCENT))
        ph.append("\n  Click  [ DISCOVER ]  in the left panel to find live hosts on your subnet.")
        ph.setTextColor(QColor(TEXT_SECONDARY))
        ph.append("\n  This table will then show:")
        ph.append("    \u25cf  IP address, MAC address and hardware vendor")
        ph.append("    \u25cf  Hostname and online/offline/unstable status")
        ph.append("    \u25cf  Per-device latency (ms) and uptime percentage")
        ph.append("    \u25cf  Last-seen timestamp")
        ph.append("\n  Double-click any row to set it as your scan target.")
        self.device_stack.addWidget(self.device_placeholder)
        self.device_stack.addWidget(self.device_table)
        self.device_stack.setCurrentIndex(0)
        self.tabs.addTab(self.device_stack, "\U0001f310 Devices")

        self.net_status_box = QTextEdit()
        self.net_status_box.setReadOnly(True)
        self.tabs.addTab(self.net_status_box, "📡 Net Status")

        self.summary_box = QTextEdit()
        self.summary_box.setReadOnly(True)
        self.tabs.addTab(self.summary_box, "📊 Summary")

        self.stats_box = QTextEdit()
        self.stats_box.setReadOnly(True)
        self.tabs.addTab(self.stats_box, "📈 Stats")

        # ── PACKET CAPTURE TAB (Wireshark-level v7.0) ───────────────────────
        self._conv_tracker = ConversationTracker()
        cap_widget = QWidget()
        cap_layout = QVBoxLayout(cap_widget)
        cap_layout.setContentsMargins(8, 8, 8, 8)
        cap_layout.setSpacing(4)

        # ── Row 1: Capture controls ──
        ctrl_bar = QHBoxLayout()
        ctrl_bar.setSpacing(6)
        self.cap_iface_input = QLineEdit()
        self.cap_iface_input.setPlaceholderText("Interface IP (blank = auto)")
        self.cap_iface_input.setMaximumWidth(170)
        self.cap_filter_proto = QComboBox()
        self.cap_filter_proto.addItems(["ALL", "TCP", "UDP", "ICMP"])
        self.cap_filter_proto.setMaximumWidth(80)
        self.cap_start_btn = QPushButton("▶  START CAPTURE")
        self.cap_start_btn.setObjectName("discoverBtn")
        self.cap_start_btn.clicked.connect(self.toggle_packet_capture)
        self.cap_clear_btn = QPushButton("🗑  CLEAR")
        self.cap_clear_btn.clicked.connect(self.clear_capture)
        self.cap_export_btn = QPushButton("💾  SAVE .PCAP")
        self.cap_export_btn.setToolTip("Export real .pcap file — open directly in Wireshark!")
        self.cap_export_btn.clicked.connect(self.export_capture)
        self.cap_export_json_btn = QPushButton("📄  JSON")
        self.cap_export_json_btn.clicked.connect(self.export_capture_json)
        self.cap_stream_btn = QPushButton("🔀  FOLLOW STREAM")
        self.cap_stream_btn.setToolTip("Follow TCP stream for selected packet")
        self.cap_stream_btn.clicked.connect(self.follow_tcp_stream)
        self.cap_conv_btn = QPushButton("💬  CONVERSATIONS")
        self.cap_conv_btn.setToolTip("Show conversation tracker")
        self.cap_conv_btn.clicked.connect(self.show_conversations)
        for w2 in [QLabel("Iface:"), self.cap_iface_input,
                   QLabel("Proto:"), self.cap_filter_proto,
                   self.cap_start_btn, self.cap_clear_btn,
                   self.cap_export_btn, self.cap_export_json_btn,
                   self.cap_stream_btn, self.cap_conv_btn]:
            ctrl_bar.addWidget(w2)
        ctrl_bar.addStretch()
        cap_layout.addLayout(ctrl_bar)

        # ── Row 2: Display filter bar (like Wireshark toolbar) ──
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(6)
        filter_lbl = QLabel("🔍 Display Filter:")
        filter_lbl.setStyleSheet(f"color:{ACCENT}; font-weight:bold; font-size:12px;")
        self.cap_host_filter = QLineEdit()
        self.cap_host_filter.setPlaceholderText("ip == 192.168.1.1  |  port 80  |  flags SYN  |  host 10.0.0.1")
        self.cap_host_filter.setToolTip("Filter: ip=<IP>  port=<NUM>  flags=<FLAG>  host=<IP>")
        self.cap_apply_filter_btn = QPushButton("Apply")
        self.cap_apply_filter_btn.setMaximumWidth(70)
        self.cap_apply_filter_btn.clicked.connect(self.apply_display_filter)
        self.cap_clear_filter_btn = QPushButton("Clear")
        self.cap_clear_filter_btn.setMaximumWidth(60)
        self.cap_clear_filter_btn.clicked.connect(self.clear_display_filter)
        self.cap_stats_label = QLabel("  Packets: 0  |  TCP: 0  UDP: 0  ICMP: 0  |  0 B")
        self.cap_stats_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px;")
        filter_bar.addWidget(filter_lbl)
        filter_bar.addWidget(self.cap_host_filter, 1)
        filter_bar.addWidget(self.cap_apply_filter_btn)
        filter_bar.addWidget(self.cap_clear_filter_btn)
        filter_bar.addStretch()
        filter_bar.addWidget(self.cap_stats_label)
        cap_layout.addLayout(filter_bar)

        # ── Packet list table (top pane) ──
        self.packet_table = QTableWidget(0, 9)
        self.packet_table.setHorizontalHeaderLabels([
            "#", "TIME", "SOURCE", "DESTINATION", "PROTO", "SRC PORT", "DST PORT", "FLAGS", "LEN"
        ])
        self.packet_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.packet_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for col, w3 in [(0, 55), (1, 105), (4, 65), (5, 80), (6, 80), (7, 110), (8, 55)]:
            self.packet_table.setColumnWidth(col, w3)
        self.packet_table.setAlternatingRowColors(False)  # We do custom coloring
        self.packet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.itemClicked.connect(self.show_packet_detail)
        self.packet_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self._packet_context_menu)

        # ── Bottom splitter: protocol tree | hex dump ──
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Protocol tree (left)
        tree_group = QGroupBox("PACKET DETAILS  (Protocol Dissector)")
        tree_layout = QVBoxLayout(tree_group)
        tree_layout.setContentsMargins(4, 4, 4, 4)
        self.packet_detail_box = QTextEdit()
        self.packet_detail_box.setReadOnly(True)
        self.packet_detail_box.setFont(QFont("Consolas", 10))
        tree_layout.addWidget(self.packet_detail_box)
        bottom_splitter.addWidget(tree_group)

        # Hex dump (right)
        hex_group = QGroupBox("HEX DUMP  (Payload bytes)")
        hex_layout = QVBoxLayout(hex_group)
        hex_layout.setContentsMargins(4, 4, 4, 4)
        self.hex_dump_box = QTextEdit()
        self.hex_dump_box.setReadOnly(True)
        self.hex_dump_box.setFont(QFont("Consolas", 10))
        self.hex_dump_box.setStyleSheet(f"background:{DARK_BG}; color:{TEXT_SECONDARY};")
        hex_layout.addWidget(self.hex_dump_box)
        bottom_splitter.addWidget(hex_group)
        bottom_splitter.setSizes([500, 500])

        # Main vertical splitter: packet list | bottom
        cap_splitter = QSplitter(Qt.Orientation.Vertical)
        cap_splitter.addWidget(self.packet_table)
        cap_splitter.addWidget(bottom_splitter)
        cap_splitter.setSizes([400, 220])
        cap_layout.addWidget(cap_splitter, 1)

        self.tabs.addTab(cap_widget, "🦈 Capture")

        # ── TRACEROUTE TAB ──────────────────────────────────────────────────
        tr_widget = QWidget()
        tr_layout = QVBoxLayout(tr_widget)
        tr_layout.setContentsMargins(8, 8, 8, 8)
        tr_bar = QHBoxLayout()
        self.tr_target_input = QLineEdit()
        self.tr_target_input.setPlaceholderText("Target IP or hostname for traceroute")
        self.tr_start_btn = QPushButton("▶  TRACE ROUTE")
        self.tr_start_btn.setObjectName("discoverBtn")
        self.tr_start_btn.clicked.connect(self.run_traceroute)
        tr_bar.addWidget(QLabel("Target:"))
        tr_bar.addWidget(self.tr_target_input, 1)
        tr_bar.addWidget(self.tr_start_btn)
        tr_layout.addLayout(tr_bar)
        self.traceroute_box = QTextEdit()
        self.traceroute_box.setReadOnly(True)
        self.traceroute_box.setFont(QFont("Consolas", 11))
        tr_layout.addWidget(self.traceroute_box, 1)
        self.tabs.addTab(tr_widget, "🛤 Traceroute")


        log_group = QGroupBox("📋  SCAN LOG")
        log_group.setStyleSheet(f"QGroupBox {{ background:{PANEL_BG}; border:1px solid {BORDER}; border-radius:8px; margin-top:10px; padding:8px; }} QGroupBox::title {{ color:{ACCENT}; background:{PANEL_BG}; font-size:10px; letter-spacing:1px; }}")
        ll = QVBoxLayout(log_group)
        ll.setContentsMargins(6, 4, 6, 6)
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont("Consolas", 11))
        self.log_box.setMinimumHeight(160)
        self.log_box.setMaximumHeight(220)
        ll.addWidget(self.log_box)
        layout.addWidget(log_group)

        return panel

    # ──────────────────────────────────────────
    #  PORT SELECTION
    # ──────────────────────────────────────────
    def open_port_selector(self):
        dlg = PortSelectDialog(self, self.ports_display_str)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            ports = dlg.get_ports()
            if ports:
                self.selected_ports    = ports
                self.ports_display_str = dlg.get_ports_display()
                self.ports_label.setText(f"{self.ports_display_str[:40]}")
                self.port_count_label.setText(f"{len(ports)} ports")
                self.append_log(f"[✓] Port selection updated: {len(ports)} port(s) selected.", "success")
            else:
                QMessageBox.warning(self, "No Ports", "No valid ports were selected.")

    def _quick_set_ports(self, ports_str: str):
        ports = PortSelectDialog._parse_ports(ports_str)
        if ports:
            self.selected_ports    = ports
            self.ports_display_str = ports_str
            self.ports_label.setText(f"{ports_str[:40]}")
            self.port_count_label.setText(f"{len(ports)} ports")
            self.append_log(f"[✓] Quick port preset: {len(ports)} port(s).", "success")

    # ──────────────────────────────────────────
    #  SCAN
    # ──────────────────────────────────────────
    def start_scan(self):
        target = self.target_input.text().strip()
        self.tr_target_input.setText(target)  # sync traceroute target

        # FIX: validate target input before proceeding
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP or hostname.")
            return
        if len(target) > 253:
            QMessageBox.warning(self, "Input Error", "Target address is too long.")
            return
        if not self.selected_ports:
            QMessageBox.warning(self, "No Ports", "Please configure at least one port.")
            return

        for tbl in [self.port_table, self.vuln_table]:
            tbl.setRowCount(0)
        self.log_box.clear()
        self.summary_box.clear()
        self.stats_box.clear()
        self.progress.setValue(0)
        self.pct_label.setText("Initialising…")
        self.status_dot.setText("  ●  SCANNING")
        self.status_dot.setStyleSheet(f"color:{ACCENT}; font-size:12px; font-weight:600; padding:0 10px;")
        self.export_btn.setEnabled(False)
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        timeout = float(self.timeout_box.currentText().replace("s",""))
        scan_techniques = {
            'service_detection': self.service_check.isChecked(),
            'vuln_scan':         self.vuln_check.isChecked(),
            'ssl_check':         self.ssl_check.isChecked(),
        }

        targets = self._expand_targets(target)
        if len(targets) > 1:
            self.append_log(f"[*] Scanning first target of {len(targets)}: {targets[0]}", "info")
            target = targets[0]

        self.append_log(f"[*] Starting scan — {len(self.selected_ports)} port(s) on {target}", "info")

        self.worker = ScanWorker(target, self.selected_ports, timeout, scan_techniques)
        self.worker.log.connect(self.append_log)
        self.worker.progress.connect(self.update_progress)
        self.worker.port_found.connect(self.add_port_row)
        self.worker.vuln_found.connect(self.add_vuln_row)
        self.worker.rate_update.connect(self.update_scan_rate)
        self.worker.service_detected.connect(lambda _: None)
        self.worker.scan_done.connect(self.on_scan_done)
        self.worker.start()
        self._update_status(f"Scanning {target} — {len(self.selected_ports)} port(s) …")
        self._scan_rate_timer_start = time.time()
        file_logger.info(f"SCAN STARTED — target={target} ports={len(self.selected_ports)}")

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.append_log("[!] Stopping scan … please wait.", "warning")
        self.stop_btn.setEnabled(False)
        QTimer.singleShot(2000, lambda: self.scan_btn.setEnabled(True))

    def on_scan_done(self, results):
        self.results = results
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.scan_history.append(results)
        ports_n = len(results.get('open_ports', []))
        vulns_n = len(results.get('vulns', []))
        dur     = results.get('scan_duration', 0)
        file_logger.info(
            f"SCAN COMPLETE — target={results.get('target')} ip={results.get('ip')} "
            f"open_ports={ports_n} cves={vulns_n} duration={dur}s"
        )
        for p in results.get('open_ports', []):
            file_logger.info(f"  OPEN PORT {p['port']}/{p.get('proto','tcp')} {p['service']} v{p.get('version','?')} os={p.get('os_hint','?')}")
        for v in results.get('vulns', []):
            file_logger.warning(f"  CVE {v['id']} [{v['severity']}] score={v['score']} exploit={v.get('edb_id','none')} {v['service']}:{v['port']}")
        ports_n = len(results.get('open_ports', []))
        vulns_n = len(results.get('vulns', []))
        dur     = results.get('scan_duration', 0)
        self._update_status(
            f"✓  Scan complete  —  {ports_n} open ports  ·  {vulns_n} CVEs  ·  {dur}s"
        )
        # Update header stat capsules
        self._update_header_stats()
        # Update pct/status dot
        self.pct_label.setText(f"Done  ·  {ports_n} open  ·  {vulns_n} CVEs  ·  {dur}s")
        crit_n = sum(1 for v in results.get('vulns',[]) if v['severity'].upper()=='CRITICAL')
        if crit_n > 0:
            self.status_dot.setText(f"  ●  {crit_n} CRITICAL")
            self.status_dot.setStyleSheet(f"color:{CRITICAL}; font-size:12px; font-weight:700; padding:0 10px;")
        elif vulns_n > 0:
            self.status_dot.setText(f"  ●  {vulns_n} VULNS")
            self.status_dot.setStyleSheet(f"color:{HIGH}; font-size:12px; font-weight:700; padding:0 10px;")
        else:
            self.status_dot.setText("  ●  CLEAN")
            self.status_dot.setStyleSheet(f"color:{LOW}; font-size:12px; font-weight:700; padding:0 10px;")
        self._build_summary(results)
        self._build_statistics()
        self.auto_export_report()
        self.tabs.setCurrentIndex(4)

    # ──────────────────────────────────────────
    #  DEVICE DISCOVERY
    # ──────────────────────────────────────────
    def start_discovery(self):
        subnet = self.subnet_input.text().strip()
        if not subnet:
            local_ip = get_local_ip()
            parts = local_ip.split(".")
            subnet = ".".join(parts[:3])
            self.subnet_input.setText(subnet)
            self.append_log(f"[✓] Auto-detected subnet: {subnet}.0/24", "success")

        self.device_table.setRowCount(0)
        self.device_stack.setCurrentIndex(0)
        self.device_row_map = {}
        self.discovered_devices = []
        self.progress.setValue(0)
        self.discover_btn.setEnabled(False)
        self.stop_discover_btn.setEnabled(True)

        self.append_log(f"[*] Starting device discovery on {subnet}.0/24 …", "info")
        self.tabs.setCurrentIndex(2)

        timeout = float(self.timeout_box.currentText().replace("s",""))
        self.discovery_worker = DeviceDiscoveryWorker(subnet, timeout)
        self.discovery_worker.device_found.connect(self.add_device_row)
        self.discovery_worker.log.connect(self.append_log)
        self.discovery_worker.progress.connect(self.update_progress)
        self.discovery_worker.done.connect(self.on_discovery_done)
        self.discovery_worker.start()
        self._update_status(f"Discovering devices on {subnet}.0/24 …")

    def stop_discovery(self):
        if self.discovery_worker:
            self.discovery_worker.stop()
        self.stop_discover_btn.setEnabled(False)
        self.discover_btn.setEnabled(True)

    def on_discovery_done(self, devices: list):
        self.discovered_devices = devices
        self.discover_btn.setEnabled(True)
        self.stop_discover_btn.setEnabled(False)
        self._update_status(f"✓  Discovery complete — {len(devices)} device(s) found.")
        self.append_log(f"[✓] {len(devices)} device(s) discovered. Double-click a device to scan it.", "success")
        self._update_header_stats()
        self._build_network_status()
        self.status_dot.setText(f"  ●  {len(devices)} HOSTS")
        self.status_dot.setStyleSheet(f"color:{LOW}; font-size:12px; font-weight:700; padding:0 10px;")

    def add_device_row(self, dev: dict):
        ip = dev["ip"]
        # Switch from placeholder to table on first device
        if self.device_stack.currentIndex() == 0:
            self.device_stack.setCurrentIndex(1)
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        self.device_row_map[ip] = row

        status_clr = {"ONLINE": ONLINE_CLR, "OFFLINE": OFFLINE_CLR, "UNSTABLE": UNSTABLE_CLR}.get(dev["status"], TEXT_SECONDARY)
        status_icon = {"ONLINE": "● ONLINE", "OFFLINE": "○ OFFLINE", "UNSTABLE": "◐ UNSTABLE"}.get(dev["status"], dev["status"])

        cols = [
            (dev["ip"],                             ACCENT),
            (dev["mac"],                            TEXT_PRIMARY),
            (dev["vendor"],                         TEXT_SECONDARY),
            (dev["hostname"],                       TEXT_PRIMARY),
            (status_icon,                           status_clr),
            (f"{dev['latency_ms']:.0f} ms",         MEDIUM if dev["latency_ms"] > 100 else LOW),
            (f"{dev.get('uptime_pct', 100.0):.1f}%", LOW),
            (dev["last_seen"],                      TEXT_SECONDARY),
        ]
        for col, (text, colour) in enumerate(cols):
            item = QTableWidgetItem(text)
            item.setForeground(QColor(colour))
            if col == 0:
                item.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            self.device_table.setItem(row, col, item)

    def update_device_status(self, update: dict):
        ip = update["ip"]
        if ip not in self.device_row_map:
            return
        row = self.device_row_map[ip]
        status   = update["status"]
        latency  = update["latency_ms"]
        uptime   = update["uptime_pct"]
        last_seen = update["last_seen"]

        status_clr  = {"ONLINE": ONLINE_CLR, "OFFLINE": OFFLINE_CLR, "UNSTABLE": UNSTABLE_CLR}.get(status, TEXT_SECONDARY)
        status_icon = {"ONLINE": "● ONLINE", "OFFLINE": "○ OFFLINE", "UNSTABLE": "◐ UNSTABLE"}.get(status, status)
        lat_clr     = CRITICAL if status == "OFFLINE" else (MEDIUM if latency > 200 else LOW)

        for col, (text, clr) in enumerate([
            (None, None), (None, None), (None, None), (None, None),
            (status_icon, status_clr),
            (f"{latency:.0f} ms", lat_clr),
            (f"{uptime:.1f}%", LOW if uptime > 80 else MEDIUM if uptime > 50 else CRITICAL),
            (last_seen, TEXT_SECONDARY),
        ]):
            if text is not None:
                item = self.device_table.item(row, col)
                if item:
                    item.setText(text)
                    item.setForeground(QColor(clr))

        for dev in self.discovered_devices:
            if dev["ip"] == ip:
                dev["status"]     = status
                dev["latency_ms"] = latency
                dev["uptime_pct"] = uptime
                dev["last_seen"]  = last_seen
                break

        self._build_network_status()

    def scan_selected_device(self, item):
        row = item.row()
        ip_item = self.device_table.item(row, 0)
        if ip_item:
            ip = ip_item.text()
            self.target_input.setText(ip)
            self.tabs.setCurrentIndex(0)
            QMessageBox.information(self, "Device Selected",
                f"Target set to {ip}.\nClick '▶ START SCAN' to scan this device.")

    # ──────────────────────────────────────────
    #  UPTIME MONITOR
    # ──────────────────────────────────────────
    def toggle_uptime_monitor(self):
        if self.uptime_worker and self.uptime_worker.isRunning():
            self.uptime_worker.stop()
            self.uptime_worker.wait()
            self.uptime_worker = None
            self.monitor_btn.setText("📡  START UPTIME MONITOR")
            self.append_log("[*] Uptime monitor stopped.", "info")
        else:
            if not self.discovered_devices:
                QMessageBox.warning(self, "No Devices", "Run a device discovery first.")
                return
            self.uptime_worker = UptimeMonitorWorker(list(self.discovered_devices), interval=30.0)
            self.uptime_worker.status_update.connect(self.update_device_status)
            self.uptime_worker.log.connect(self.append_log)
            self.uptime_worker.start()
            self.monitor_btn.setText("⏹  STOP UPTIME MONITOR")
            self.append_log(f"[✓] Uptime monitor started — pinging {len(self.discovered_devices)} device(s) every 30s.", "success")

    # ──────────────────────────────────────────
    #  NETWORK STATUS DASHBOARD
    # ──────────────────────────────────────────
    def _build_network_status(self):
        box = self.net_status_box
        box.clear()

        if not self.discovered_devices:
            box.setTextColor(QColor(TEXT_SECONDARY))
            box.append("\n\n  No network discovery data available.\n")
            box.setTextColor(QColor(ACCENT))
            box.append("  Click  [ DISCOVER ]  in the left panel to scan your subnet for live hosts.")
            box.append("\n  Once discovery is complete, this panel will show:")
            box.setTextColor(QColor(TEXT_SECONDARY))
            box.append("    ● Online / Offline / Unstable device status")
            box.append("    ● Network health percentage")
            box.append("    ● Per-device latency and uptime tracking")
            box.append("    ● Vendor distribution chart")
            return
        box = self.net_status_box
        box.clear()

        online   = [d for d in self.discovered_devices if d["status"] == "ONLINE"]
        offline  = [d for d in self.discovered_devices if d["status"] == "OFFLINE"]
        unstable = [d for d in self.discovered_devices if d["status"] == "UNSTABLE"]

        def write(text, color=TEXT_PRIMARY):
            box.setTextColor(QColor(color))
            box.append(text)

        write("═" * 72, ACCENT)
        write("  NETWORK STATUS DASHBOARD", ACCENT)
        write("═" * 72, ACCENT)
        write(f"  Last Updated : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}", TEXT_SECONDARY)
        write(f"  Total Devices: {len(self.discovered_devices)}", TEXT_PRIMARY)
        write("")
        write(f"  ● ONLINE   : {len(online)}", ONLINE_CLR)
        write(f"  ◐ UNSTABLE : {len(unstable)}", UNSTABLE_CLR)
        write(f"  ○ OFFLINE  : {len(offline)}", OFFLINE_CLR)
        write("")

        total = len(self.discovered_devices)
        health = len(online) / total * 100 if total else 0
        bar_len = 50
        filled = int(bar_len * health / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        bar_clr = LOW if health > 80 else (MEDIUM if health > 50 else CRITICAL)
        write(f"  Network Health : {health:.1f}%", bar_clr)
        write(f"  [{bar}]", bar_clr)
        write("")

        if online:
            write("  ── ONLINE DEVICES ──────────────────────────────", ACCENT)
            write(f"  {'IP':<18} {'MAC':<20} {'VENDOR':<18} {'LATENCY':<10} {'UPTIME'}", TEXT_SECONDARY)
            write("  " + "─" * 68, BORDER)
            for d in sorted(online, key=lambda x: [int(i) for i in x["ip"].split(".")]):
                lat_clr = MEDIUM if d["latency_ms"] > 100 else LOW
                write(
                    f"  {d['ip']:<18} {d['mac']:<20} {d['vendor']:<18} "
                    f"{d['latency_ms']:.0f}ms{'':<5} {d.get('uptime_pct', 100.0):.1f}%",
                    lat_clr
                )
            write("")

        if unstable:
            write("  ── UNSTABLE DEVICES ────────────────────────────", UNSTABLE_CLR)
            for d in unstable:
                write(f"  {d['ip']:<18} ◐  {d['latency_ms']:.0f}ms   uptime:{d.get('uptime_pct', 0.0):.1f}%", UNSTABLE_CLR)
            write("")

        if offline:
            write("  ── OFFLINE DEVICES ─────────────────────────────", OFFLINE_CLR)
            for d in offline:
                write(f"  {d['ip']:<18} ○  last seen: {d.get('last_seen', '—')}", OFFLINE_CLR)
            write("")

        vendors = defaultdict(int)
        for d in self.discovered_devices:
            vendors[d["vendor"]] += 1
        if vendors:
            write("  ── VENDOR DISTRIBUTION ─────────────────────────", ACCENT)
            for v, cnt in sorted(vendors.items(), key=lambda x: -x[1]):
                write(f"  {v:<25} : {cnt} device(s)", TEXT_PRIMARY)
            write("")

        write("═" * 72, ACCENT)

    # ──────────────────────────────────────────
    #  HELPER: LOCAL NETWORK DETECT
    # ──────────────────────────────────────────
    def detect_local_network(self):
        try:
            local_ip = get_local_ip()
            parts = local_ip.split(".")
            if len(parts) >= 3:
                net = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                self.target_input.setText(net)
                self.subnet_input.setText(".".join(parts[:3]))
                self.append_log(f"[✓] Detected local network: {net}  (host: {local_ip})", "success")
        except Exception as e:
            self.append_log(f"[-] Could not detect local network: {str(e)}", "error")

    def _expand_targets(self, target):
        if "-" in target:
            parts = target.split(".")
            if len(parts) == 4:
                last = parts[3]
                if "-" in last:
                    a, b = map(int, last.split("-"))
                    base = ".".join(parts[:3])
                    return [f"{base}.{i}" for i in range(a, b + 1)]
        return [target]

    # ──────────────────────────────────────────
    #  TABLE ROWS
    # ──────────────────────────────────────────
    def add_port_row(self, info):
        row = self.port_table.rowCount()
        self.port_table.insertRow(row)
        risky = {21: "High", 23: "High", 445: "Critical", 3389: "High", 5900: "Medium", 22: "Medium"}
        risk = risky.get(info["port"], "Low")
        risk_clr = {"Critical": CRITICAL, "High": HIGH, "Medium": MEDIUM, "Low": LOW}.get(risk, TEXT_SECONDARY)
        proto_suffix = f"/{info.get('proto','tcp').lower()}"

        cols = [
            (str(info["port"]) + proto_suffix,   ACCENT),
            (info["service"],                     TEXT_PRIMARY),
            (info.get("version", "N/A"),          INFO),
            (info.get("state", "open").upper(),   LOW),
            (info["banner"][:120] or "—",         TEXT_SECONDARY),
            (risk,                                risk_clr),
            (info.get("os_hint", ""),             TEXT_SECONDARY),
        ]
        for col, (text, colour) in enumerate(cols):
            item = QTableWidgetItem(text)
            item.setForeground(QColor(colour))
            item.setData(Qt.ItemDataRole.UserRole, info)
            self.port_table.setItem(row, col, item)
        # Log to file
        file_logger.info(f"PORT OPEN {info['port']}/{info.get('proto','tcp')} {info['service']} v{info.get('version','?')} banner={info['banner'][:80]}")

    def _port_table_context_menu(self, pos):
        """Right-click context menu on the Ports table."""
        item = self.port_table.itemAt(pos)
        if not item:
            return
        info = item.data(Qt.ItemDataRole.UserRole)
        if not info:
            return
        ip      = info.get("ip", self.target_input.text().strip())
        port    = info.get("port", 0)
        service = info.get("service", "")
        menu    = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{ background:{CARD_BG}; border:1px solid {BORDER_BRIGHT}; border-radius:6px; padding:4px; }}
            QMenu::item {{ padding:6px 20px; color:{TEXT_PRIMARY}; font-size:12px; }}
            QMenu::item:selected {{ background:{ACCENT_DIM}; color:{ACCENT}; border-radius:4px; }}
            QMenu::separator {{ background:{BORDER}; height:1px; margin:3px 8px; }}
        """)

        def add_action(label, slot):
            a = QAction(label, self)
            a.triggered.connect(slot)
            menu.addAction(a)

        add_action(f"📋  Copy IP  ({ip})",            lambda: self._copy_to_clipboard(ip))
        add_action(f"📋  Copy Port  ({port})",         lambda: self._copy_to_clipboard(str(port)))
        add_action(f"📋  Copy  IP:Port",               lambda: self._copy_to_clipboard(f"{ip}:{port}"))
        menu.addSeparator()

        # Open in browser (HTTP/HTTPS services)
        if service in ("HTTP", "HTTP-Alt", "HTTP-Dev") or port in (80, 8080, 8090, 3000, 5000):
            add_action(f"🌐  Open in Browser  (http://{ip}:{port})",
                       lambda: self._open_in_browser(f"http://{ip}:{port}"))
        if service in ("HTTPS", "HTTPS-Alt") or port in (443, 8443):
            add_action(f"🌐  Open in Browser  (https://{ip}:{port})",
                       lambda: self._open_in_browser(f"https://{ip}:{port}"))

        menu.addSeparator()
        add_action(f"🔍  Scan only this port  ({port})",
                   lambda: self._scan_single_port(ip, port))
        add_action(f"🎯  Set as scan target  ({ip})",
                   lambda: self.target_input.setText(ip))
        add_action(f"🔀  Traceroute to  {ip}",
                   lambda: self._quick_traceroute(ip))
        menu.addSeparator()
        add_action("🔍  Search CVEs for this service",
                   lambda: self._search_cves_for_port(info))
        menu.exec(self.port_table.viewport().mapToGlobal(pos))

    def _open_in_browser(self, url: str):
        import webbrowser
        webbrowser.open(url)
        self.append_log(f"[*] Opening browser: {url}", "info")

    def _scan_single_port(self, ip: str, port: int):
        self.target_input.setText(ip)
        self._quick_set_ports(str(port))
        self.start_scan()

    def _quick_traceroute(self, ip: str):
        self.tr_target_input.setText(ip)
        self.tabs.setCurrentIndex(8)  # Traceroute tab
        self.run_traceroute()

    def _search_cves_for_port(self, info: dict):
        service = info.get("service", "")
        self.append_log(f"[*] Searching CVEs for {service} (port {info.get('port')}) …", "info")
        self.tabs.setCurrentIndex(1)  # Switch to vulns tab

    def add_vuln_row(self, info):
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        sev     = info["severity"].upper()
        sev_clr = sev_color(sev)
        published   = info.get("published", "Unknown")[:10]
        exploit     = info.get("exploitability", "Unknown")
        edb_id      = info.get("edb_id", "")
        has_exploit = info.get("exploit_available", bool(edb_id))
        edb_text    = f"✔ {edb_id}" if has_exploit and edb_id else ("✔ Known" if has_exploit else "—")
        edb_clr     = CRITICAL if has_exploit else TEXT_SECONDARY

        for col, (text, clr) in enumerate([
            (info["id"],          TEXT_PRIMARY),
            (info["service"],     TEXT_PRIMARY),
            (str(info["port"]),   TEXT_PRIMARY),
            (str(info["score"]),  ACCENT),
            (sev,                 sev_clr),
            (published,           TEXT_SECONDARY),
            (exploit,             TEXT_SECONDARY),
            (edb_text,            edb_clr),
        ]):
            item = QTableWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, info)
            item.setForeground(QColor(clr))
            if col == 4:
                item.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            if col == 7 and has_exploit:
                item.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
            self.vuln_table.setItem(row, col, item)
        # Log CVE to file
        file_logger.warning(f"CVE {info['id']} [{sev}] score={info['score']} exploit={edb_text} {info['service']}:{info['port']}")

    def show_vuln_detail(self, item):
        info = item.data(Qt.ItemDataRole.UserRole)
        if not info:
            return
        mitigation = info.get("mitigation", get_mitigation(info["service"], info["severity"]))
        edb_line   = ""
        if info.get("exploit_available"):
            edb_line = (
                f"\n─── EXPLOIT-DB ─────────────────────────\n"
                f"EDB ID:          {info.get('edb_id','Unknown')}\n"
                f"Exploit Type:    {info.get('exploit_type','Unknown')}\n"
                f"Verified:        {'✔ Yes' if info.get('exploit_verified') else '○ No'}\n"
                f"⚠  PUBLIC EXPLOIT AVAILABLE — PATCH IMMEDIATELY\n"
            )
        cpe_line = f"CPE:             {info.get('cpe', '—')}\n" if info.get('cpe') else ""
        QMessageBox.information(self, f"CVE Details — {info['id']}",
            f"CVE ID:          {info['id']}\n"
            f"Service:         {info['service']} (Port {info['port']})\n"
            f"CVSS Score:      {info['score']}\n"
            f"Severity:        {info['severity']}\n"
            f"Published:       {info.get('published', 'Unknown')}\n"
            f"Exploitability:  {info.get('exploitability', 'Unknown')}\n"
            f"{cpe_line}"
            f"\nDescription:\n{info['description']}\n"
            f"{edb_line}"
            f"\n─── MITIGATION STRATEGY ───\n{mitigation}"
        )

    # ──────────────────────────────────────────
    #  LOG
    # ──────────────────────────────────────────
    def append_log(self, message, level):
        colour = {
            "info":     TEXT_SECONDARY,
            "success":  LOW,
            "error":    CRITICAL,
            "warning":  MEDIUM,
            "vuln":     HIGH,
            "critical": CRITICAL,
        }.get(level, TEXT_PRIMARY)
        ts = datetime.now().strftime("%H:%M:%S")
        cursor = self.log_box.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_box.setTextCursor(cursor)
        self.log_box.setTextColor(QColor(colour))
        self.log_box.append(f"[{ts}] {message}")
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())

        # ── Write to rotating log file ──
        log_level = {
            "error": logging.ERROR, "critical": logging.CRITICAL,
            "warning": logging.WARNING, "vuln": logging.WARNING,
            "success": logging.INFO, "info": logging.INFO,
        }.get(level, logging.DEBUG)
        file_logger.log(log_level, message)

    def clear_logs(self):
        reply = QMessageBox.question(self, "Clear Data", "Clear all scan results and logs?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.log_box.clear()
            self.port_table.setRowCount(0)
            self.vuln_table.setRowCount(0)
            self.device_table.setRowCount(0)
            self.device_stack.setCurrentIndex(0)
            self.summary_box.clear()
            self.stats_box.clear()
            self.results = {}
            self.discovered_devices = []
            self.device_row_map = {}
            self._build_network_status()
            self.export_btn.setEnabled(False)
            self.append_log("[✓] All data cleared.", "success")

    def update_scan_rate(self, rate: int, done: int, total: int):
        """Live ports/sec counter update."""
        pct = int((done / total) * 100) if total > 0 else 0
        self.pct_label.setText(f"Scanning…  {pct}%  ·  {rate:,} ports/sec")
        elapsed = time.time() - getattr(self, '_scan_rate_timer_start', time.time())
        remaining = max(0, (total - done) / rate) if rate > 0 else 0
        if remaining > 0:
            m, s = divmod(int(remaining), 60)
            self.eta_label.setText(f"ETA {m}m {s}s" if m else f"ETA {s}s")
        else:
            self.eta_label.setText("")

    def update_progress(self, pct):
        self.progress.setValue(pct)
        self.pct_label.setText(f"Scanning…  {pct}%")
        if pct > 0:
            self.status_dot.setText("  ●  SCANNING")
            self.status_dot.setStyleSheet(f"color:{ACCENT}; font-size:12px; font-weight:600; padding:0 10px;")

    # ──────────────────────────────────────────
    #  SUMMARY & STATISTICS
    # ──────────────────────────────────────────
    def _build_summary(self, r):
        ports = r.get("open_ports", [])
        vulns = r.get("vulns", [])
        box   = self.summary_box
        box.clear()

        def w(text, clr=TEXT_PRIMARY):
            box.setTextColor(QColor(clr))
            box.append(text)

        w("═" * 72, ACCENT)
        w("  NETSCAN PRO v5.0 — SCAN SUMMARY", ACCENT)
        w("═" * 72, ACCENT)
        w(f"  Target          : {r.get('target', '—')}", TEXT_SECONDARY)
        w(f"  IP Address      : {r.get('ip', '—')}", TEXT_SECONDARY)
        w(f"  Hostname        : {r.get('hostname', '—')}", TEXT_SECONDARY)
        w(f"  Ports Scanned   : {len(self.selected_ports)} selected", TEXT_SECONDARY)
        w(f"  Scan Started    : {r.get('start_time', '—')}", TEXT_SECONDARY)
        w(f"  Scan Completed  : {r.get('end_time', '—')}", TEXT_SECONDARY)
        w(f"  Scan Duration   : {r.get('scan_duration', 0)} seconds", TEXT_SECONDARY)
        w("")
        w(f"  Open Ports      : {len(ports)}", TEXT_PRIMARY)
        w(f"  CVEs Found      : {len(vulns)}", TEXT_PRIMARY)
        w("")

        critical = sum(1 for v in vulns if v["severity"].upper() == "CRITICAL")
        high     = sum(1 for v in vulns if v["severity"].upper() == "HIGH")
        medium   = sum(1 for v in vulns if v["severity"].upper() == "MEDIUM")
        low      = sum(1 for v in vulns if v["severity"].upper() == "LOW")

        # Also count port-based risks (e.g. SMB port 445 = Critical even with no CVEs)
        PORT_RISK = {21: "HIGH", 23: "HIGH", 445: "CRITICAL", 3389: "HIGH", 5900: "MEDIUM", 22: "MEDIUM"}
        for p in ports:
            pr = PORT_RISK.get(p["port"], "LOW")
            if pr == "CRITICAL":
                critical += 1
            elif pr == "HIGH":
                high += 1
            elif pr == "MEDIUM":
                medium += 1
            else:
                low += 1

        w("  RISK BREAKDOWN", ACCENT)
        w("─" * 72, ACCENT)
        w(f"  ● CRITICAL  : {critical}", CRITICAL if critical > 0 else TEXT_SECONDARY)
        w(f"  ● HIGH      : {high}", HIGH if high > 0 else TEXT_SECONDARY)
        w(f"  ● MEDIUM    : {medium}", MEDIUM if medium > 0 else TEXT_SECONDARY)
        w(f"  ● LOW       : {low}", LOW if low > 0 else TEXT_SECONDARY)

        if ports:
            w("")
            w("  OPEN PORTS & VERSIONS", ACCENT)
            w("─" * 72, ACCENT)
            w(f"  {'PORT':<8} {'SERVICE':<18} {'VERSION':<14} {'RISK'}", TEXT_SECONDARY)
            w("  " + "─" * 60, BORDER)
            for p in ports:
                risky = {21: "High", 23: "High", 445: "Critical", 3389: "High", 5900: "Medium"}
                risk = risky.get(p["port"], "Low")
                risk_clr = {"Critical": CRITICAL, "High": HIGH, "Medium": MEDIUM, "Low": LOW}.get(risk, LOW)
                icon = "⚠" if p["port"] in [21, 23, 445, 3389] else "✓"
                w(f"  {p['port']:<8} {p['service']:<18} {p.get('version', 'N/A'):<14} {icon} {risk}", risk_clr)

        if vulns:
            w("")
            w("  VULNERABILITY DETAILS WITH MITIGATIONS (TOP 10)", ACCENT)
            w("─" * 72, ACCENT)
            for v in vulns[:10]:
                # FIX: use sev_color() for correct colour mapping
                s_clr = sev_color(v["severity"])
                w(f"  {v['id']:<20} [{v['severity']:8}]  Score:{v['score']:>5}  {v['service']}:{v['port']}", s_clr)
                w(f"    {v['description'][:120]}", TEXT_SECONDARY)
                # FIX: show mitigation per CVE (satisfies project proposal requirement)
                mitigation = v.get("mitigation", get_mitigation(v["service"], v["severity"]))
                w(f"    ▶ MITIGATION: {mitigation[:200]}", WARNING)
                w("")

        w("")
        w("  SECURITY RECOMMENDATIONS", ACCENT)
        w("─" * 72, ACCENT)
        if not vulns:
            w("  ✓ No vulnerabilities detected. System appears secure.", LOW)
        else:
            for rec in [
                "1. Immediately patch CRITICAL & HIGH severity CVEs",
                "2. Disable or firewall unnecessary open services",
                "3. Update all services to latest versions",
                "4. Implement network segmentation and least-privilege access",
                "5. Enable IDS/IPS monitoring and alerting",
                "6. Schedule regular scans to track security posture changes",
                "7. Review and harden SSL/TLS configurations",
                "8. Enable logging and audit trails on all exposed services",
            ]:
                w(f"  {rec}", TEXT_PRIMARY)

        w("")
        w("═" * 72, ACCENT)

    def _build_statistics(self):
        r = self.results
        if not r:
            return
        box = self.stats_box
        box.clear()

        def w(text, clr=TEXT_SECONDARY):
            box.setTextColor(QColor(clr))
            box.append(text)

        def bar(label, val, max_val, width=40, clr=ACCENT):
            filled = int(width * val / max_val) if max_val > 0 else 0
            b = "█" * filled + "░" * (width - filled)
            w(f"  {label:<28} [{b}]  {val}", clr)

        w("═" * 72, ACCENT)
        w("  NETSCAN PRO v5.0 — SCAN STATISTICS & METRICS", ACCENT)
        w("═" * 72, ACCENT)

        ports   = r.get("open_ports", [])
        vulns   = r.get("vulns", [])
        duration = max(r.get("scan_duration", 1), 0.001)
        total_ports = len(self.selected_ports)

        w("")
        w("  ── PERFORMANCE ─────────────────────────────────────────────", ACCENT)
        speed = total_ports / duration
        w(f"  Total ports scanned : {total_ports}")
        w(f"  Open ports found    : {len(ports)}  ({len(ports)/total_ports*100:.1f}% hit rate)")
        w(f"  Scan duration       : {r.get('scan_duration', 0)}s")
        w(f"  Scan speed          : ~{speed:.0f} ports/sec")
        w(f"  CVEs discovered     : {len(vulns)}")
        # Speed bar
        w("")
        w("  SCAN SPEED (ports/sec — 1000 is excellent)", TEXT_SECONDARY)
        bar("Scan speed", min(int(speed), 1000), 1000, 40, ACCENT)
        if ports:
            bar("Open port rate", len(ports), total_ports, 40, LOW)

        if ports:
            w("")
            w("  ── PORT DISTRIBUTION (by range) ────────────────────────────", ACCENT)
            ranges = {"Well-known  (0–1023)": 0, "Registered  (1024–49151)": 0, "Dynamic     (49152–65535)": 0}
            for p in ports:
                pn = p["port"]
                if pn < 1024:    ranges["Well-known  (0–1023)"] += 1
                elif pn < 49152: ranges["Registered  (1024–49151)"] += 1
                else:            ranges["Dynamic     (49152–65535)"] += 1
            total_open = len(ports) or 1
            for k, v in ranges.items():
                if v:
                    bar(k, v, total_open, 40, INFO)

            w("")
            w("  ── TOP OPEN PORTS (bar chart) ───────────────────────────────", ACCENT)
            port_nums = sorted(set(p["port"] for p in ports))
            for pn in port_nums[:15]:
                svc = next((p["service"] for p in ports if p["port"] == pn), "Unknown")
                risky = {21: CRITICAL, 23: CRITICAL, 445: CRITICAL, 3389: HIGH, 5900: MEDIUM, 22: MEDIUM}
                clr = risky.get(pn, LOW)
                bar(f":{pn} {svc}", 1, 1, 20, clr)

            w("")
            w("  ── VERSION SUMMARY ─────────────────────────────────────────", ACCENT)
            w(f"  {'SERVICE':<20} {'VERSION':<20} {'PORT':<8} {'OS HINT'}", TEXT_SECONDARY)
            w("  " + "─" * 65, BORDER)
            for p in ports:
                os_h = p.get("os_hint", "")
                w(f"  {p['service']:<20} {p.get('version', 'N/A'):<20} {p['port']:<8} {os_h}", INFO)

        if vulns:
            w("")
            w("  ── CVSS SCORE DISTRIBUTION (bar chart) ─────────────────────", ACCENT)
            buckets = {"Critical  (9.0–10.0)": 0, "High      (7.0–8.9)": 0, "Medium    (4.0–6.9)": 0, "Low       (0.1–3.9)": 0}
            for v in vulns:
                s = v["score"]
                if s >= 9:   buckets["Critical  (9.0–10.0)"] += 1
                elif s >= 7: buckets["High      (7.0–8.9)"] += 1
                elif s >= 4: buckets["Medium    (4.0–6.9)"] += 1
                elif s > 0:  buckets["Low       (0.1–3.9)"] += 1
            max_count = max(buckets.values()) or 1
            clr_map = {"Critical": CRITICAL, "High": HIGH, "Medium": MEDIUM, "Low": LOW}
            for k, v in buckets.items():
                clr = next((c for label, c in clr_map.items() if label in k), TEXT_SECONDARY)
                if v:
                    bar(k, v, max_count, 40, clr)

            w("")
            w("  ── CVE EXPLOITABILITY ──────────────────────────────────────", ACCENT)
            exploit_scores = [float(v.get("exploitability", 0)) for v in vulns if str(v.get("exploitability", "")).replace(".","").isdigit()]
            if exploit_scores:
                avg_exploit = sum(exploit_scores) / len(exploit_scores)
                w(f"  Average exploitability score: {avg_exploit:.2f} / 10.0", CRITICAL if avg_exploit > 7 else HIGH)
                bar("Avg exploitability", int(avg_exploit * 10), 100, 40, CRITICAL if avg_exploit > 7 else HIGH)

        # Capture stats (if any)
        if self.captured_packets:
            w("")
            w("  ── PACKET CAPTURE SUMMARY ──────────────────────────────────", ACCENT)
            total_pkts = len(self.captured_packets)
            proto_counts = {}
            for pkt in self.captured_packets:
                proto_counts[pkt.get("proto", "?")] = proto_counts.get(pkt.get("proto", "?"), 0) + 1
            w(f"  Total packets captured : {total_pkts}")
            max_proto = max(proto_counts.values()) if proto_counts else 1
            for proto, cnt in sorted(proto_counts.items(), key=lambda x: -x[1]):
                clr = ACCENT if proto == "TCP" else LOW if proto == "UDP" else MEDIUM
                bar(f"  {proto}", cnt, max_proto, 40, clr)

        w("")
        w("═" * 72, ACCENT)


    # ──────────────────────────────────────────
    #  PACKET CAPTURE — Wireshark-level v7.0
    # ──────────────────────────────────────────
    def _parse_display_filter(self, text: str) -> dict:
        """Parse Wireshark-style display filter string into filter dict."""
        f = {"host": "", "port": 0, "flags": ""}
        text = text.strip()
        if not text:
            return f
        # ip == x.x.x.x  or  host x.x.x.x
        m = re.search(r'(?:ip\s*==\s*|host\s+)([\d.]+)', text, re.I)
        if m:
            f["host"] = m.group(1)
        # port N  or  tcp.port == N
        m = re.search(r'(?:port\s+|\.port\s*==\s*)(\d+)', text, re.I)
        if m:
            f["port"] = int(m.group(1))
        # flags SYN  /  tcp.flags.syn == 1  /  flags RST
        m = re.search(r'flags?\s+([A-Z]+)', text, re.I)
        if m:
            f["flags"] = m.group(1).upper()
        return f

    def apply_display_filter(self):
        """Re-filter captured_packets list and rebuild table."""
        ftext = self.cap_host_filter.text().strip()
        f = self._parse_display_filter(ftext)
        self.packet_table.setRowCount(0)
        for pkt in self.captured_packets:
            if f["host"] and f["host"] not in (pkt.get("src_ip",""), pkt.get("dst_ip","")):
                continue
            if f["port"] and f["port"] not in (pkt.get("src_port",0), pkt.get("dst_port",0)):
                continue
            if f["flags"] and f["flags"] not in pkt.get("flags","").upper():
                continue
            self._add_packet_row_ui(pkt)
        self.append_log(f"[🔍] Display filter applied: {ftext or '(none)'} — {self.packet_table.rowCount()} packets shown", "info")

    def clear_display_filter(self):
        self.cap_host_filter.clear()
        self.apply_display_filter()

    def toggle_packet_capture(self):
        if self.capture_worker and self.capture_worker.isRunning():
            self.capture_worker.stop()
            self.capture_worker.wait(3000)
            self.capture_worker = None
            self.cap_start_btn.setText("▶  START CAPTURE")
            self.cap_start_btn.setObjectName("discoverBtn")
            self.append_log("[*] Packet capture stopped.", "info")
            self.update_capture_stats({"total": len(self.captured_packets), "TCP":0,"UDP":0,"ICMP":0,"Other":0,"bytes":0})
        else:
            iface  = self.cap_iface_input.text().strip()
            proto  = self.cap_filter_proto.currentText()
            ftext  = self.cap_host_filter.text().strip()
            f      = self._parse_display_filter(ftext)
            self.capture_worker = PacketCaptureWorker(
                iface_ip=iface, filter_proto=proto,
                bpf_host=f["host"], filter_port=f["port"], filter_flags=f["flags"]
            )
            self.capture_worker.packet_received.connect(self.add_packet_row)
            self.capture_worker.stats_update.connect(self.update_capture_stats)
            self.capture_worker.log.connect(self.append_log)
            self.capture_worker.start()
            self.cap_start_btn.setText("⏹  STOP CAPTURE")
            self.append_log("[*] Packet capture starting… (requires Administrator / sudo)", "info")

    def add_packet_row(self, pkt: dict):
        self.captured_packets.append(pkt)
        self._conv_tracker.add_packet(pkt)
        self._add_packet_row_ui(pkt)

    def _add_packet_row_ui(self, pkt: dict):
        """Insert one packet row with Wireshark-style colorization."""
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        fg, bg = packet_row_color(pkt)
        src_svc = port_to_service(pkt.get("src_port", 0))
        dst_svc = port_to_service(pkt.get("dst_port", 0))
        cols = [
            str(row + 1),
            pkt.get("timestamp", ""),
            f"{pkt.get('src_ip','')}",
            f"{pkt.get('dst_ip','')}",
            pkt.get("proto", ""),
            f"{pkt.get('src_port','')} {src_svc}",
            f"{pkt.get('dst_port','')} {dst_svc}",
            pkt.get("flags", ""),
            str(pkt.get("length", 0)),
        ]
        bg_color = QColor(bg)
        for col, text in enumerate(cols):
            item = QTableWidgetItem(text)
            item.setForeground(QColor(fg))
            item.setBackground(bg_color)
            item.setData(Qt.ItemDataRole.UserRole, pkt)
            self.packet_table.setItem(row, col, item)
        # Auto-scroll only if near bottom
        sb = self.packet_table.verticalScrollBar()
        if sb.value() >= sb.maximum() - 5:
            self.packet_table.scrollToBottom()

    def show_packet_detail(self, item):
        """Show full protocol dissector tree + hex dump — Wireshark style."""
        pkt = item.data(Qt.ItemDataRole.UserRole)
        if not pkt:
            return

        # ── Protocol Tree (left panel) ──
        box = self.packet_detail_box
        box.clear()
        def w(text, clr=TEXT_PRIMARY, bold=False):
            box.setTextColor(QColor(clr))
            if bold:
                box.setFontWeight(700)
            box.append(text)
            box.setFontWeight(400)

        layers = dissect_packet(pkt)
        LAYER_COLORS = [ACCENT, "#88ff88", "#ffcc00", "#ff88ff", "#b0c4ff", TEXT_SECONDARY]
        for i, (layer_name, fields) in enumerate(layers):
            clr = LAYER_COLORS[i % len(LAYER_COLORS)]
            w(f"▼ {layer_name}", clr, bold=True)
            for k, v in fields.items():
                w(f"     {k:<24}: {v}", TEXT_SECONDARY)
            w("")

        # ── Hex Dump (right panel) ──
        hex_box = self.hex_dump_box
        hex_box.clear()
        hex_raw = pkt.get("hex", "")
        hex_box.setTextColor(QColor(TEXT_SECONDARY))
        if hex_raw:
            hex_box.setTextColor(QColor(ACCENT))
            hex_box.append(f"  Payload hex dump — {len(hex_raw)//2} bytes shown")
            hex_box.setTextColor(QColor(TEXT_SECONDARY))
            hex_box.append(f"  {'OFFSET':<6}  {'HEX (16 bytes per row)':<49}  │  ASCII")
            hex_box.append("  " + "─" * 70)
            hex_box.setTextColor(QColor("#8b949e"))
            hex_box.append(format_hex_dump(hex_raw))
        else:
            hex_box.setTextColor(QColor(TEXT_SECONDARY))
            hex_box.append("  No payload data available for this packet.")

    def _packet_context_menu(self, pos):
        """Right-click context menu on packet table."""
        item = self.packet_table.itemAt(pos)
        if not item:
            return
        pkt = item.data(Qt.ItemDataRole.UserRole)
        if not pkt:
            return
        menu = QMenu(self)
        actions = [
            ("🔀 Follow TCP Stream",      self.follow_tcp_stream),
            ("📋 Copy Source IP",          lambda: self._copy_to_clipboard(pkt.get("src_ip",""))),
            ("📋 Copy Destination IP",     lambda: self._copy_to_clipboard(pkt.get("dst_ip",""))),
            ("🔍 Filter → this IP",        lambda: self._quick_filter(f"ip == {pkt.get('src_ip','')}")),
            ("🔍 Filter → this port",      lambda: self._quick_filter(f"port {pkt.get('dst_port','')}")),
            ("🔍 Filter → this protocol",  lambda: self._quick_filter(pkt.get("proto",""))),
            ("💬 Show Conversations",       self.show_conversations),
        ]
        for label, slot in actions:
            a = QAction(label, self)
            a.triggered.connect(slot)
            menu.addAction(a)
        menu.exec(self.packet_table.viewport().mapToGlobal(pos))

    def _copy_to_clipboard(self, text: str):
        QApplication.clipboard().setText(text)
        self.append_log(f"[✓] Copied to clipboard: {text}", "success")

    def _quick_filter(self, text: str):
        self.cap_host_filter.setText(text)
        self.apply_display_filter()

    def update_capture_stats(self, stats: dict):
        total = stats.get("total", len(self.captured_packets))
        byt   = stats.get("bytes", sum(p.get("length",0) for p in self.captured_packets))
        # Format bytes
        if byt >= 1_000_000:
            byt_str = f"{byt/1_000_000:.1f} MB"
        elif byt >= 1_000:
            byt_str = f"{byt/1_000:.1f} KB"
        else:
            byt_str = f"{byt} B"
        self.cap_stats_label.setText(
            f"  📦 {total} pkts  |  "
            f"TCP:{stats.get('TCP',0)}  UDP:{stats.get('UDP',0)}  "
            f"ICMP:{stats.get('ICMP',0)}  Other:{stats.get('Other',0)}  |  {byt_str}"
        )

    def clear_capture(self):
        self.packet_table.setRowCount(0)
        self.captured_packets.clear()
        self.packet_detail_box.clear()
        self.hex_dump_box.clear()
        self._conv_tracker.clear()
        self.cap_stats_label.setText("  Packets: 0  |  TCP: 0  UDP: 0  ICMP: 0  |  0 B")

    def export_capture(self):
        """Export real .pcap file — openable in Wireshark."""
        if not self.captured_packets:
            QMessageBox.information(self, "No Data", "No packets captured yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP File",
            f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap",
            "PCAP Files (*.pcap);;All Files (*)"
        )
        if not path:
            return
        try:
            with PcapWriter(path) as pcap:
                for pkt in self.captured_packets:
                    raw_hex = pkt.get("raw", "")
                    if raw_hex:
                        try:
                            raw_bytes = bytes.fromhex(raw_hex)
                        except Exception:
                            raw_bytes = b""
                    else:
                        # Reconstruct minimal packet representation
                        raw_bytes = b""
                    if raw_bytes:
                        pcap.write_packet(raw_bytes, pkt.get("ts_float", time.time()))
            self.append_log(f"[✓] PCAP saved: {path}  (open in Wireshark)", "success")
            QMessageBox.information(self, "PCAP Saved",
                f"Real PCAP file saved:\n{path}\n\nYou can open this directly in Wireshark!")
        except Exception as e:
            self.append_log(f"[-] PCAP export failed: {str(e)}", "error")

    def export_capture_json(self):
        """Export capture as JSON."""
        if not self.captured_packets:
            QMessageBox.information(self, "No Data", "No packets captured yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Capture",
            f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON (*.json)"
        )
        if not path:
            return
        try:
            export_data = []
            for p in self.captured_packets:
                d = {k: v for k, v in p.items() if k != "raw"}  # Exclude raw bytes blob
                export_data.append(d)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            self.append_log(f"[✓] JSON capture saved: {path}", "success")
        except Exception as e:
            self.append_log(f"[-] JSON export failed: {str(e)}", "error")

    def follow_tcp_stream(self):
        """Follow TCP stream for the selected packet — show all packets between same src/dst pair."""
        row = self.packet_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No Packet", "Select a packet first.")
            return
        item = self.packet_table.item(row, 0)
        if not item:
            return
        pkt = item.data(Qt.ItemDataRole.UserRole)
        if not pkt:
            return
        if pkt.get("proto") != "TCP":
            QMessageBox.information(self, "Not TCP", "Follow TCP Stream only works on TCP packets.")
            return

        src_ip, dst_ip = pkt.get("src_ip",""), pkt.get("dst_ip","")
        src_p,  dst_p  = pkt.get("src_port",0), pkt.get("dst_port",0)

        stream_pkts = [
            p for p in self.captured_packets
            if p.get("proto") == "TCP" and (
                (p.get("src_ip")==src_ip and p.get("dst_ip")==dst_ip and
                 p.get("src_port")==src_p and p.get("dst_port")==dst_p)
                or
                (p.get("src_ip")==dst_ip and p.get("dst_ip")==src_ip and
                 p.get("src_port")==dst_p and p.get("dst_port")==src_p)
            )
        ]

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Follow TCP Stream — {src_ip}:{src_p} ↔ {dst_ip}:{dst_p}")
        dlg.resize(900, 600)
        dlg.setStyleSheet(self.styleSheet())
        lay = QVBoxLayout(dlg)
        info = QLabel(f"  Stream: {src_ip}:{src_p} ↔ {dst_ip}:{dst_p}   |   {len(stream_pkts)} packets")
        info.setStyleSheet(f"color:{ACCENT}; font-weight:bold; padding:6px;")
        lay.addWidget(info)
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setFont(QFont("Consolas", 11))
        lay.addWidget(txt)

        for p in stream_pkts:
            direction = "→" if p.get("src_ip") == src_ip else "←"
            clr = ACCENT if direction == "→" else LOW
            txt.setTextColor(QColor(clr))
            txt.append(f"  {p.get('timestamp','')}  {direction}  [{p.get('flags','')}]  len={p.get('length',0)}")
            if p.get("hex"):
                txt.setTextColor(QColor(TEXT_SECONDARY))
                txt.append(format_hex_dump(p["hex"]))
            txt.append("")

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        dlg.exec()

    def show_conversations(self):
        """Show conversation tracker dialog — like Wireshark Statistics → Conversations."""
        convs = self._conv_tracker.get_all()
        dlg = QDialog(self)
        dlg.setWindowTitle("Conversation Tracker — Endpoints & Traffic")
        dlg.resize(1000, 500)
        dlg.setStyleSheet(self.styleSheet())
        lay = QVBoxLayout(dlg)

        hdr = QLabel(f"  {len(convs)} unique conversations  —  sorted by packet count")
        hdr.setStyleSheet(f"color:{ACCENT}; font-weight:bold; padding:6px;")
        lay.addWidget(hdr)

        tbl = QTableWidget(len(convs), 7)
        tbl.setHorizontalHeaderLabels(["IP A", "IP B", "Packets", "Bytes", "Protocols", "Ports", "Last Seen"])
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl.setAlternatingRowColors(True)

        for r, c in enumerate(convs):
            byte_str = f"{c['bytes']:,} B" if c['bytes'] < 1000 else f"{c['bytes']/1000:.1f} KB"
            vals = [c["ip_a"], c["ip_b"], str(c["packets"]), byte_str,
                    c["protos"], c["ports"], c["last"]]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if col == 2:
                    item.setForeground(QColor(ACCENT))
                elif col == 3:
                    item.setForeground(QColor(LOW))
                tbl.setItem(r, col, item)
        lay.addWidget(tbl)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        dlg.exec()

    # ──────────────────────────────────────────
    #  TRACEROUTE
    # ──────────────────────────────────────────
    def run_traceroute(self):
        target = self.tr_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Enter a target IP or hostname.")
            return
        self.traceroute_box.clear()
        self.tr_start_btn.setEnabled(False)

        def do_trace():
            box = self.traceroute_box
            def w(text, clr=TEXT_PRIMARY):
                box.setTextColor(QColor(clr))
                box.append(text)

            try:
                ip = socket.gethostbyname(target)
            except Exception:
                ip = target

            w(f"  Traceroute to {target} ({ip})", ACCENT)
            w(f"  {'HOP':<6} {'IP ADDRESS':<20} {'HOSTNAME':<35} {'LATENCY'}", TEXT_SECONDARY)
            w("  " + "─" * 68, BORDER)

            if platform.system().lower() == "windows":
                cmd = ["tracert", "-d", "-w", "2000", target]
            else:
                cmd = ["traceroute", "-n", "-w", "2", "-m", "30", target]

            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                hop = 0
                for line in proc.stdout:
                    line = line.strip()
                    if not line or line.startswith("Tracing") or line.startswith("traceroute"):
                        continue
                    # Parse Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                    # Parse Linux:   "  1  192.168.1.1  0.543 ms  0.512 ms  0.498 ms"
                    parts = line.split()
                    if not parts:
                        continue
                    try:
                        hop = int(parts[0])
                    except ValueError:
                        continue

                    hop_ip = "* * *"
                    latency = "timeout"
                    for part in parts[1:]:
                        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', part):
                            hop_ip = part
                            break
                    for part in parts[1:]:
                        if re.match(r'[<\d]', part) and 'ms' in parts[parts.index(part)+1:parts.index(part)+2]:
                            latency = f"{part} ms"
                            break

                    try:
                        hostname = socket.gethostbyaddr(hop_ip)[0] if hop_ip != "* * *" else "—"
                    except Exception:
                        hostname = hop_ip

                    clr = LOW if latency != "timeout" else OFFLINE_CLR
                    w(f"  {hop:<6} {hop_ip:<20} {hostname[:33]:<35} {latency}", clr)
                    box.verticalScrollBar().setValue(box.verticalScrollBar().maximum())

                proc.wait()
                w("")
                w(f"  Traceroute complete ({hop} hops)", LOW)
            except FileNotFoundError:
                w("  [!] traceroute / tracert not found on this system.", CRITICAL)
            except Exception as e:
                w(f"  [!] Traceroute failed: {e}", CRITICAL)

            self.tr_start_btn.setEnabled(True)

        t = threading.Thread(target=do_trace, daemon=True)
        t.start()

    # ──────────────────────────────────────────
    #  EXPORT
    # ──────────────────────────────────────────
    def export_report(self):
        if not self.results and not self.discovered_devices:
            QMessageBox.information(self, "No Data", "Run a scan or discovery first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", f"netscan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "JSON (*.json);;HTML (*.html);;Text (*.txt)"
        )
        if not path:
            return
        try:
            if path.endswith(".json"):
                data = {"scan": self.results, "devices": self.discovered_devices}
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            elif path.endswith(".html"):
                self._export_html(path)
            else:
                self._export_text(path)
            self.append_log(f"[✓] Report saved: {path}", "success")
        except Exception as e:
            self.append_log(f"[-] Export failed: {str(e)}", "error")

    def _export_html(self, path):
        r     = self.results
        ports = r.get("open_ports", [])
        vulns = r.get("vulns", [])
        devs  = self.discovered_devices

        port_rows = "".join(
            f"<tr><td>{p['port']}</td><td>{p['service']}</td>"
            f"<td style='color:#00d9ff'>{p.get('version', 'N/A')}</td>"
            f"<td style='color:#00cc66'>OPEN</td><td>{p['banner'][:100]}</td></tr>"
            for p in ports
        )

        def dev_status_color(d):
            return ONLINE_CLR if d['status'] == "ONLINE" else OFFLINE_CLR

        # FIX: sev_color() now used correctly for all severity levels in HTML export
        vuln_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
            "<td style='color:{}'>{}</td><td>{}</td><td style='font-size:11px'>{}</td></tr>".format(
                v['id'], v['service'], v['port'], v['score'],
                sev_color(v['severity']), v['severity'],
                v.get('published', '')[:10],
            )
            for v in vulns
        )

        mitigation_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td style='font-size:11px;color:#aaa'>{}</td></tr>".format(
                v['id'], v['severity'],
                v.get('mitigation', get_mitigation(v['service'], v['severity']))[:300].replace('\n', '<br>')
            )
            for v in vulns
        )

        dev_rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
            "<td style='color:{}'>{}</td><td>{:.0f}ms</td><td>{:.1f}%</td></tr>".format(
                d['ip'], d['mac'], d['vendor'], d['hostname'],
                dev_status_color(d), d['status'], d['latency_ms'], d.get('uptime_pct', 100.0)
            )
            for d in devs
        )

        html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>NetScan Pro v8.0 Report</title>
<style>
body{{background:#0d1117;color:#e6edf3;font-family:Consolas,monospace;padding:20px}}
h1{{color:#00d9ff;letter-spacing:4px}} h2{{color:#00d9ff;border-bottom:1px solid #30363d;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th{{background:#161b22;color:#8b949e;padding:10px;text-align:left;border-bottom:2px solid #00d9ff}}
td{{padding:8px 10px;border-bottom:1px solid #30363d}}
tr:hover{{background:#161b22}}
</style></head><body>
<h1>NETSCAN PRO v8.0 — REPORT</h1>
<p>Target: {r.get('target','—')} ({r.get('ip','—')}) | Duration: {r.get('scan_duration',0)}s | Generated: {datetime.now():%Y-%m-%d %H:%M:%S}</p>
<h2>🔌 Open Ports ({len(ports)})</h2>
<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Status</th><th>Banner</th></tr>
{port_rows or '<tr><td colspan=5>None found</td></tr>'}</table>
<h2>🔒 Vulnerabilities ({len(vulns)})</h2>
<table><tr><th>CVE</th><th>Service</th><th>Port</th><th>Score</th><th>Severity</th><th>Published</th><th>Exploitability</th></tr>
{vuln_rows or '<tr><td colspan=7>None found</td></tr>'}</table>
<h2>🛡 Mitigation Strategies</h2>
<table><tr><th>CVE</th><th>Severity</th><th>Recommended Action</th></tr>
{mitigation_rows or '<tr><td colspan=3>No vulnerabilities found</td></tr>'}</table>
<h2>🌐 Network Devices ({len(devs)})</h2>
<table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Status</th><th>Latency</th><th>Uptime</th></tr>
{dev_rows or '<tr><td colspan=7>No discovery run</td></tr>'}</table>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _export_text(self, path):
        # FIX: added encoding="utf-8" to handle non-ASCII hostnames/banners
        with open(path, "w", encoding="utf-8") as f:
            f.write("NETSCAN PRO v8.0 — SCAN REPORT\n" + "=" * 60 + "\n")
            r = self.results
            f.write(f"Target: {r.get('target','—')}\nIP: {r.get('ip','—')}\n")
            f.write(f"Ports scanned: {len(self.selected_ports)}\n")
            f.write(f"Open ports: {len(r.get('open_ports',[]))}\n")
            f.write(f"CVEs: {len(r.get('vulns',[]))}\n")
            f.write(f"Devices discovered: {len(self.discovered_devices)}\n")
            f.write("\n--- OPEN PORTS ---\n")
            for p in r.get("open_ports", []):
                f.write(f"  {p['port']}/tcp  {p['service']}  v{p.get('version','N/A')}\n")
            f.write("\n--- VULNERABILITIES & MITIGATIONS ---\n")
            for v in r.get("vulns", []):
                f.write(f"  {v['id']}  [{v['severity']}]  Score:{v['score']}  {v['service']}:{v['port']}\n")
                f.write(f"    {v['description'][:150]}\n")
                mitigation = v.get("mitigation", get_mitigation(v["service"], v["severity"]))
                f.write(f"    MITIGATION: {mitigation}\n\n")
            f.write("\n--- NETWORK DEVICES ---\n")
            for d in self.discovered_devices:
                f.write(f"  {d['ip']}  {d['mac']}  {d['vendor']}  {d['status']}  {d['latency_ms']:.0f}ms\n")

    def auto_export_report(self):
        try:
            from pathlib import Path
            import tempfile
            temp_dir = Path(tempfile.gettempdir()) / "NetScanPro"
            temp_dir.mkdir(exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            p = temp_dir / f"scan_{ts}.json"
            with open(p, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2)
            self.append_log(f"[✓] Auto-saved: {p}", "success")
        except Exception:
            pass

    # ──────────────────────────────────────────
    #  SETTINGS
    # ──────────────────────────────────────────
    def _load_settings(self):
        saved_t = self.settings.value("timeout", "1.0s")
        if not saved_t.endswith("s"):
            saved_t += "s"
        self.timeout_box.setCurrentText(saved_t)
        self.service_check.setChecked(self.settings.value("service_detection", True, type=bool))
        self.vuln_check.setChecked(self.settings.value("vuln_scan", True, type=bool))
        self.ssl_check.setChecked(self.settings.value("ssl_check", True, type=bool))
        saved_ports = self.settings.value("ports_display", "1-1000")
        self._quick_set_ports(saved_ports)
        recent = self.settings.value("recent_targets", [])
        if recent and isinstance(recent, list) and recent:
            self.target_input.setText(recent[0])

    def auto_save_state(self):
        self.settings.setValue("timeout", self.timeout_box.currentText())
        self.settings.setValue("service_detection", self.service_check.isChecked())
        self.settings.setValue("vuln_scan", self.vuln_check.isChecked())
        self.settings.setValue("ssl_check", self.ssl_check.isChecked())
        self.settings.setValue("ports_display", self.ports_display_str)
        target = self.target_input.text().strip()
        if target:
            recent = self.settings.value("recent_targets", [])
            if target not in recent:
                recent.insert(0, target)
                self.settings.setValue("recent_targets", recent[:5])

    def _update_status(self, msg):
        self.statusBar().showMessage(f"  {msg}")

    # ──────────────────────────────────────────
    #  HELP
    # ──────────────────────────────────────────
    def show_help(self):
        QMessageBox.information(self, "NetScan Pro v8.0 Help", """
<h2>NetScan Pro v8.0 — Help</h2>

<h3>Port Selection</h3>
<p>Click <b>"Configure Ports …"</b> to pick predefined profiles or enter custom ports like <code>22, 80, 443, 8000-9000</code>.<br>
Use the quick buttons (Top 100, Web, All) for instant presets.</p>

<h3>Network Device Discovery</h3>
<p>Enter a subnet prefix (e.g. 192.168.1) and click <b>Discover Devices</b> to find all live hosts.<br>
Double-click any device in the table to auto-fill it as a scan target.</p>

<h3>Uptime / Downtime Monitor</h3>
<p>After discovery, click <b>Start Uptime Monitor</b> to ping devices every 30 seconds and track
online / offline / unstable status with uptime percentage.</p>

<h3>Firmware / Version Detection</h3>
<p>Banner grabbing extracts version strings for SSH, Apache, nginx, vsftpd, MySQL and more,
shown in the "Version" column of the Ports tab.</p>

<h3>Vulnerability Scanning with Mitigations (v4.0)</h3>
<p>CVEs are fetched from the NVD database. Each vulnerability now includes a <b>mitigation strategy</b>.
Click any CVE row to see full details and remediation advice.</p>

<h3>Export</h3>
<p>Reports (JSON / HTML / TXT) include open ports with versions, CVEs with mitigation advice, and full device list with MAC addresses.</p>
""")

    def closeEvent(self, event):
        for w in [self.worker, self.discovery_worker, self.uptime_worker, self.capture_worker]:
            if w and w.isRunning():
                w.stop()
                w.wait(2000)
        event.accept()


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("NetScan Pro")
    app.setApplicationVersion("8.0")
    app.setOrganizationName("NetScanPro")

    win = NetScanPro()
    win.show()
    sys.exit(app.exec())

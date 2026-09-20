#!/usr/bin/env python3
"""
camera_finder.py
=================
Discover IP/WiFi cameras on your local network and view their live stream.

Two discovery methods are used:
  1. ONVIF WS-Discovery  - most modern IP cameras (Hikvision, Dahua, Reolink,
     Amcrest, TP-Link VIGI, generic ONVIF cameras, etc.) answer a UDP
     multicast probe and identify themselves.
  2. Port scan           - sweeps your subnet for hosts with camera-typical
     ports open (554 RTSP, 80/8080 HTTP, 8000, 37777, 34567 etc.) as a
     fallback for devices that don't speak ONVIF.

Viewing is done with OpenCV, which can open RTSP/HTTP(MJPEG) video streams.

Requirements:
    pip install opencv-python

Usage:
    # Just discover cameras on your network
    python3 camera_finder.py --scan

    # Discover, then pick one to view
    python3 camera_finder.py

    # View a specific stream URL directly
    python3 camera_finder.py --url rtsp://user:pass@192.168.1.50:554/stream1
"""

import argparse
import ipaddress
import socket
import struct
import sys
import threading
import time
import uuid
from queue import Queue

# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------

CAMERA_PORTS = [554, 80, 8080, 8000, 8899, 37777, 34567, 2020, 88, 9000]
RTSP_PORT = 554

COMMON_RTSP_PATHS = [
    "/stream1",
    "/live/ch0",
    "/live/ch00_0",
    "/h264/ch1/main/av_stream",
    "/cam/realmonitor?channel=1&subtype=0",   # Dahua/Amcrest style
    "/Streaming/Channels/101",                 # Hikvision style
    "/videoMain",
    "/videostream.cgi",
    "/11",
]


def get_local_ip_and_subnet():
    """Find this machine's LAN IP and derive a /24 subnet to scan."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    network = ipaddress.ip_network(local_ip + "/24", strict=False)
    return local_ip, network


def check_port(ip, port, timeout=0.4):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except OSError:
        return False


def scan_host(ip, results, lock):
    open_ports = [p for p in CAMERA_PORTS if check_port(ip, p)]
    if open_ports:
        with lock:
            results.append((str(ip), open_ports))


def port_scan_network(network, max_threads=100):
    """Threaded sweep of the subnet for hosts with camera-like open ports."""
    print(f"[*] Port-scanning {network} for camera-like open ports "
          f"({CAMERA_PORTS}) ...")
    results = []
    lock = threading.Lock()
    q = Queue()

    for ip in network.hosts():
        q.put(ip)

    def worker():
        while not q.empty():
            try:
                ip = q.get_nowait()
            except Exception:
                return
            scan_host(ip, results, lock)
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return sorted(results, key=lambda r: tuple(int(p) for p in r[0].split(".")))


# --------------------------------------------------------------------------
# ONVIF WS-Discovery (UDP multicast probe, no extra dependencies)
# --------------------------------------------------------------------------

WSD_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{msg_id}</w:MessageID>
    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action a:mustUnderstand="true" xmlns:a="http://www.w3.org/2003/05/soap-envelope">
        http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe
    </w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

WSD_MCAST_GRP = "239.255.255.250"
WSD_MCAST_PORT = 3702


def onvif_discover(timeout=4):
    """Send a WS-Discovery probe and collect responses from ONVIF cameras."""
    print("[*] Sending ONVIF WS-Discovery probe ...")
    msg = WSD_PROBE.format(msg_id=uuid.uuid4())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ttl = struct.pack('b', 4)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    sock.settimeout(timeout)

    devices = {}
    try:
        sock.sendto(msg.encode("utf-8"), (WSD_MCAST_GRP, WSD_MCAST_PORT))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                # Pull the XAddrs (device service URL) out of the reply if present
                xaddr = None
                if "<d:XAddrs>" in text:
                    xaddr = text.split("<d:XAddrs>")[1].split("</d:XAddrs>")[0].strip()
                devices[ip] = xaddr
            except socket.timeout:
                break
    finally:
        sock.close()

    return devices


# --------------------------------------------------------------------------
# Viewing
# --------------------------------------------------------------------------

def view_stream(url):
    try:
        import cv2
    except ImportError:
        print("[!] OpenCV is required to view the stream.")
        print("    Install it with: pip install opencv-python")
        sys.exit(1)

    print(f"[*] Opening stream: {url}")
    print("    Press 'q' in the video window to quit.")
    cap = cv2.VideoCapture(url)

    if not cap.isOpened():
        print("[!] Could not open the stream. Check the URL, credentials, "
              "and that the camera allows this connection.")
        return

    while True:
        ret, frame = cap.read()
        if not ret:
            print("[!] Lost connection to stream.")
            break
        cv2.imshow("Camera Feed (press q to quit)", frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()


def try_common_rtsp_urls(ip, username=None, password=None):
    """Best-effort: try a handful of common RTSP paths for a given IP."""
    auth = f"{username}:{password}@" if username else ""
    candidates = [f"rtsp://{auth}{ip}:{RTSP_PORT}{path}" for path in COMMON_RTSP_PATHS]
    return candidates


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Discover and view WiFi/IP cameras on your LAN.")
    parser.add_argument("--scan", action="store_true", help="Only discover cameras, don't prompt to view.")
    parser.add_argument("--url", help="Directly view a known stream URL (rtsp:// or http://).")
    parser.add_argument("--user", help="Username for RTSP auth (used with discovered IPs).")
    parser.add_argument("--password", help="Password for RTSP auth (used with discovered IPs).")
    args = parser.parse_args()

    if args.url:
        view_stream(args.url)
        return

    local_ip, network = get_local_ip_and_subnet()
    print(f"[*] Local IP: {local_ip}   Scanning subnet: {network}\n")

    onvif_devices = onvif_discover()
    scan_results = port_scan_network(network)

    print("\n=== ONVIF devices found ===")
    if onvif_devices:
        for ip, xaddr in onvif_devices.items():
            print(f"  {ip}  -> {xaddr or '(no service URL returned)'}")
    else:
        print("  None (camera may not support ONVIF, or blocks multicast).")

    print("\n=== Hosts with camera-like open ports ===")
    if scan_results:
        for ip, ports in scan_results:
            print(f"  {ip}  open ports: {ports}")
    else:
        print("  None found.")

    if args.scan:
        return

    # Build a candidate list to offer the user
    candidate_ips = sorted(set(list(onvif_devices.keys()) + [ip for ip, _ in scan_results]))
    if not candidate_ips:
        print("\n[!] No candidate cameras found. Try running with sudo/admin "
              "privileges, double-check you're on the same subnet/VLAN as "
              "the camera, or pass --url directly if you already know it.")
        return

    print("\nCandidate camera IPs:")
    for i, ip in enumerate(candidate_ips, 1):
        print(f"  [{i}] {ip}")

    choice = input("\nPick a number to try viewing (or press Enter to skip): ").strip()
    if not choice:
        return
    try:
        ip = candidate_ips[int(choice) - 1]
    except (ValueError, IndexError):
        print("Invalid choice.")
        return

    urls = try_common_rtsp_urls(ip, args.user, args.password)
    print(f"\n[*] Trying common RTSP paths on {ip} ...")
    for url in urls:
        print(f"    Attempting: {url}")
        # Quick check: is RTSP port even open first (already scanned), then try to view.
        view_stream(url)
        again = input("Did that show video? (y/n, n = try next path): ").strip().lower()
        if again == "y":
            return
    print("\n[!] None of the common paths worked. Check your camera's manual "
          "or app for its exact RTSP URL format, then run:\n"
          "    python3 camera_finder.py --url rtsp://user:pass@<ip>:554/<path>")


if __name__ == "__main__":
    main()

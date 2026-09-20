#!/usr/bin/env python3
"""
camera_toolkit.py
==================
All-in-one tool to discover, query, and view WiFi/IP cameras on your LAN.

Subcommands:
    scan    Discover cameras on your network (ONVIF WS-Discovery + port scan)
    view    Open a stream URL (RTSP or HTTP/MJPEG) in a viewer window
    onvif   Query an ONVIF camera's device/media service for its real RTSP URL

Requirements:
    pip install opencv-python requests

Examples:
    # Discover cameras on your subnet
    python3 camera_toolkit.py scan

    # View a known stream directly
    python3 camera_toolkit.py view --url "rtsp://admin:admin123456@192.168.1.192:8554/profile0"

    # Ask an ONVIF camera for its real stream URL
    python3 camera_toolkit.py onvif --device-url http://192.168.1.192:6688/onvif/device_service \
        --user admin --password admin123456 --auth-mode basic

Notes:
    - Some cameras (especially budget "cloud P2P" bulb/PTZ cameras) don't speak real
      ONVIF/RTSP at all and only work through their vendor's app. Others DO expose a
      real RTSP server on a non-standard port (8554 is common) even when their
      primary ONVIF media service is locked down or non-functional - it's worth
      testing both `scan` and a direct `view` with a few common ports/paths.
"""

import argparse
import base64
import hashlib
import ipaddress
import os
import re
import socket
import struct
import sys
import threading
import time
import uuid
from queue import Queue

# --------------------------------------------------------------------------
# CONFIG - edit these and just run `python3 camera_toolkit.py` with no
# arguments to view the stream directly, no prompts or flags needed.
# --------------------------------------------------------------------------

CAMERA_IP = "192.168.1.192"
RTSP_PORT = 8554
RTSP_PATH = "/profile0"
USERNAME = "admin"
PASSWORD = "admin123456"

# Only used by the `onvif` subcommand / ONVIF lookups
ONVIF_PORT = 6688
ONVIF_AUTH_MODE = "basic"  # "digest", "basic", or "none"

DEFAULT_STREAM_URL = f"rtsp://{USERNAME}:{PASSWORD}@{CAMERA_IP}:{RTSP_PORT}{RTSP_PATH}"
DEFAULT_ONVIF_DEVICE_URL = f"http://{CAMERA_IP}:{ONVIF_PORT}/onvif/device_service"

# --------------------------------------------------------------------------
# Shared constants
# --------------------------------------------------------------------------

# Common ports used by IP/WiFi cameras for RTSP, HTTP, ONVIF, and vendor-specific
# services. 8554 is a common *alternate* RTSP port (some brands, e.g. Anjia/AJ-
# series cameras, use this instead of the standard 554).
CAMERA_PORTS = [554, 8554, 80, 8080, 8000, 8899, 37777, 34567, 2020, 88, 9000, 6688]
RTSP_PORTS = [554, 8554]

COMMON_RTSP_PATHS = [
    "/profile0",                                # Anjia/AJ- series
    "/profile1",
    "/stream1",
    "/live/ch0",
    "/live/ch00_0",
    "/h264/ch1/main/av_stream",
    "/cam/realmonitor?channel=1&subtype=0",     # Dahua/Amcrest style
    "/Streaming/Channels/101",                  # Hikvision style
    "/videoMain",
    "/videostream.cgi",
    "/11",
]


# --------------------------------------------------------------------------
# scan: network discovery (ONVIF WS-Discovery + port scan)
# --------------------------------------------------------------------------

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
                xaddr = None
                if "<d:XAddrs>" in text:
                    xaddr = text.split("<d:XAddrs>")[1].split("</d:XAddrs>")[0].strip()
                devices[ip] = xaddr
            except socket.timeout:
                break
    finally:
        sock.close()

    return devices


def try_common_rtsp_urls(ip, username=None, password=None):
    """Build candidate RTSP URLs from common ports/paths for a given IP."""
    auth = f"{username}:{password}@" if username else ""
    candidates = []
    for port in RTSP_PORTS:
        for path in COMMON_RTSP_PATHS:
            candidates.append(f"rtsp://{auth}{ip}:{port}{path}")
    return candidates


def cmd_scan(args):
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

    if args.scan_only:
        return

    candidate_ips = sorted(set(list(onvif_devices.keys()) + [ip for ip, _ in scan_results]))
    if not candidate_ips:
        print("\n[!] No candidate cameras found. Try running with sudo/admin "
              "privileges, double-check you're on the same subnet/VLAN as "
              "the camera, or pass `view --url` directly if you already know it.")
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
    print(f"\n[*] Trying common RTSP ports/paths on {ip} ...")
    for url in urls:
        print(f"    Attempting: {url}")
        view_stream(url)
        again = input("Did that show video? (y/n, n = try next): ").strip().lower()
        if again == "y":
            return
    print("\n[!] None of the common combinations worked. Try `onvif` to ask the "
          "camera directly for its stream URL, or check the camera manual/app.")


# --------------------------------------------------------------------------
# view: open an RTSP/HTTP stream with OpenCV
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


def cmd_view(args):
    view_stream(args.url)


# --------------------------------------------------------------------------
# onvif: query a camera's ONVIF device/media service for its real RTSP URL
# --------------------------------------------------------------------------

def wsse_header(username, password):
    """Build a WS-Security UsernameToken header with password digest."""
    nonce = os.urandom(16)
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sha1 = hashlib.sha1()
    sha1.update(nonce + created.encode("utf-8") + password.encode("utf-8"))
    digest = base64.b64encode(sha1.digest()).decode("utf-8")
    nonce_b64 = base64.b64encode(nonce).decode("utf-8")

    return f"""
    <s:Header>
      <Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <UsernameToken>
          <Username>{username}</Username>
          <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</Password>
          <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</Nonce>
          <wsu:Created>{created}</wsu:Created>
        </UsernameToken>
      </Security>
    </s:Header>"""


def soap_request(url, body, username=None, password=None, auth_mode="digest"):
    """
    auth_mode:
      "digest" - WS-Security UsernameToken PasswordDigest in the SOAP header (ONVIF spec default)
      "basic"  - plain HTTP Basic Auth header, no WS-Security (many cheap cameras only support this)
      "none"   - no credentials at all
    """
    import requests

    if auth_mode == "digest" and username:
        header = wsse_header(username, password)
    else:
        header = "<s:Header/>"

    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
{header}
  <s:Body>
    {body}
  </s:Body>
</s:Envelope>"""

    headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
    auth = None
    if auth_mode == "basic" and username:
        auth = (username, password)

    resp = requests.post(url, data=envelope.encode("utf-8"), headers=headers, auth=auth, timeout=6)
    return resp


def get_media_service_url(device_url, username, password, auth_mode):
    body = '<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl"><Category>Media</Category></GetCapabilities>'
    resp = soap_request(device_url, body, username, password, auth_mode)
    resp.raise_for_status()
    m = re.search(r"<(?:\w+:)?Media>.*?<(?:\w+:)?XAddr>(.*?)</(?:\w+:)?XAddr>", resp.text, re.S)
    if not m:
        raise RuntimeError("Could not find Media service XAddr in response:\n" + resp.text[:500])
    return m.group(1).strip()


def get_profile_tokens(media_url, username, password, auth_mode):
    body = '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>'
    resp = soap_request(media_url, body, username, password, auth_mode)
    resp.raise_for_status()
    tokens = re.findall(r'<(?:\w+:)?Profiles[^>]*token="([^"]+)"', resp.text)
    return tokens


def get_stream_uri(media_url, profile_token, username, password, auth_mode):
    body = f"""<GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">
      <StreamSetup>
        <Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>
        <Transport xmlns="http://www.onvif.org/ver10/schema">
          <Protocol>RTSP</Protocol>
        </Transport>
      </StreamSetup>
      <ProfileToken>{profile_token}</ProfileToken>
    </GetStreamUri>"""
    resp = soap_request(media_url, body, username, password, auth_mode)
    resp.raise_for_status()
    m = re.search(r"<(?:\w+:)?Uri>(.*?)</(?:\w+:)?Uri>", resp.text, re.S)
    if not m:
        raise RuntimeError("Could not find stream Uri in response:\n" + resp.text[:500])
    return m.group(1).strip()


def cmd_onvif(args):
    import requests
    auth_mode = args.auth_mode

    try:
        print(f"[*] Asking device service for Media service address (auth={auth_mode}) ...")
        media_url = get_media_service_url(args.device_url, args.user, args.password, auth_mode)
        print(f"    Media service: {media_url}")

        print("[*] Fetching media profiles ...")
        tokens = get_profile_tokens(media_url, args.user, args.password, auth_mode)
        if not tokens:
            print("[!] No profiles found.")
            sys.exit(1)
        print(f"    Found {len(tokens)} profile(s): {tokens}")

        for token in tokens:
            uri = get_stream_uri(media_url, token, args.user, args.password, auth_mode)
            if args.user and "://" in uri and "@" not in uri:
                scheme, rest = uri.split("://", 1)
                uri_with_auth = f"{scheme}://{args.user}:{args.password}@{rest}"
            else:
                uri_with_auth = uri
            print(f"\n  Profile '{token}':")
            print(f"    Raw URL:  {uri}")
            print(f"    With auth: {uri_with_auth}")

    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code in (400, 401):
            print(f"[!] Camera rejected the request ({e.response.status_code}). "
                  "Double-check --user/--password, or try a different --auth-mode "
                  "(e.g. --auth-mode basic instead of the default 'digest').")
        else:
            print(f"[!] HTTP error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed: {e}")
        print("    Some cameras don't implement ONVIF media services in a fully "
              "functional way even if the device service responds. Try the "
              "`scan` or `view` subcommands with common RTSP ports (554, 8554) "
              "and paths as a fallback.")
        sys.exit(1)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Discover, query, and view WiFi/IP cameras on your LAN. "
                     "Run with no arguments to view the stream configured at "
                     "the top of this file (CONFIG section).")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Discover cameras on the network.")
    p_scan.add_argument("--scan-only", action="store_true",
                         help="Only print discovery results, don't prompt to view.")
    p_scan.add_argument("--user", default=USERNAME, help="Username to try when viewing a candidate.")
    p_scan.add_argument("--password", default=PASSWORD, help="Password to try when viewing a candidate.")
    p_scan.set_defaults(func=cmd_scan)

    p_view = sub.add_parser("view", help="View a stream URL directly.")
    p_view.add_argument("--url", default=DEFAULT_STREAM_URL,
                         help='Stream URL. Defaults to the CONFIG values at the top of this file.')
    p_view.set_defaults(func=cmd_view)

    p_onvif = sub.add_parser("onvif", help="Ask an ONVIF camera for its real stream URL.")
    p_onvif.add_argument("--device-url", default=DEFAULT_ONVIF_DEVICE_URL,
                          help="ONVIF device service URL. Defaults to the CONFIG values at the top of this file.")
    p_onvif.add_argument("--user", default=USERNAME, help="Camera username")
    p_onvif.add_argument("--password", default=PASSWORD, help="Camera password")
    p_onvif.add_argument("--auth-mode", choices=["digest", "basic", "none"], default=ONVIF_AUTH_MODE,
                          help="Auth method: 'digest' (ONVIF WS-Security), "
                               "'basic' (plain HTTP Basic Auth), or 'none'. "
                               "Defaults to the CONFIG value at the top of this file.")
    p_onvif.set_defaults(func=cmd_onvif)

    args = parser.parse_args()

    # No subcommand given: just view the configured stream directly.
    if args.command is None:
        view_stream(DEFAULT_STREAM_URL)
        return

    args.func(args)


if __name__ == "__main__":
    main()

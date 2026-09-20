#!/usr/bin/env python3
"""
onvif_get_url.py
=================
Ask an ONVIF camera directly for its real RTSP stream URL, instead of
guessing common paths. This talks to the camera's ONVIF "device service"
(the URL your discovery step found, e.g. http://192.168.1.192:6688/onvif/device_service),
asks it for its Media service, asks that for its profiles, then asks for
the StreamUri of each profile.

Requirements:
    pip install requests

Usage:
    python3 onvif_get_url.py --device-url http://192.168.1.192:6688/onvif/device_service \
        --user admin --password yourpassword

    # If the camera needs no auth, just omit --user/--password.
"""

import argparse
import base64
import hashlib
import os
import re
import sys
import time
import uuid

import requests

NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
}


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


def main():
    parser = argparse.ArgumentParser(description="Get the real RTSP stream URL from an ONVIF camera.")
    parser.add_argument("--device-url", required=True, help="ONVIF device service URL, e.g. http://192.168.1.192:6688/onvif/device_service")
    parser.add_argument("--user", default=None, help="Camera username")
    parser.add_argument("--password", default=None, help="Camera password")
    parser.add_argument("--auth-mode", choices=["digest", "basic", "none"], default="digest",
                         help="Auth method to use: 'digest' (ONVIF WS-Security, default), "
                              "'basic' (plain HTTP Basic Auth - try this if digest gives 400/401 "
                              "on a cheap/generic camera), or 'none'.")
    args = parser.parse_args()
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
            # Inject credentials into the URL for convenience, if given
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
        print("    Some cameras use plain-text auth instead of WS-Security "
              "digest, or need Basic Auth in the HTTP headers instead. "
              "Try checking your camera's manual/app for its exact RTSP URL "
              "as a fallback.")
        sys.exit(1)


if __name__ == "__main__":
    main()

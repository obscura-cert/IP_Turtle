import requests
import socket
import sys
from colorama import Fore, Style, init

init(autoreset=True)

IPINFO_TOKEN = ''  # Optional: Put your ipinfo.io token here if you have one
IPQUALITYSCORE_KEY = ''  # Optional: https://www.ipqualityscore.com/documentation/proxy-detection/overview

def is_private_ip(ip):
    try:
        ip_parts = list(map(int, ip.split(".")))
        return (
            ip_parts[0] == 10 or
            (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or
            (ip_parts[0] == 192 and ip_parts[1] == 168)
        )
    except:
        return False

def get_ip_info(ip):
    try:
        print(f"\n{Fore.CYAN}[+] Collecting info for: {ip}\n")

        if is_private_ip(ip):
            print(f"{Fore.YELLOW}[⚠️] Private/Reserved IP detected. Limited data may be available.\n")

        # Reverse DNS
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except:
            rdns = "Not Found"

        print(f"{Fore.YELLOW}[🔁] Reverse DNS: {rdns}")

        # IP geolocation
        ipinfo_url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_TOKEN:
            ipinfo_url += f"?token={IPINFO_TOKEN}"

        geo = requests.get(ipinfo_url).json()

        print(f"\n{Fore.GREEN}[🌍] IP Details:")
        print(f"{Fore.WHITE}     IP           : {geo.get('ip', 'N/A')}")
        print(f"{Fore.WHITE}     Hostname     : {geo.get('hostname', 'N/A')}")
        print(f"{Fore.WHITE}     City         : {geo.get('city', 'N/A')}")
        print(f"{Fore.WHITE}     Region       : {geo.get('region', 'N/A')}")
        print(f"{Fore.WHITE}     Country      : {geo.get('country', 'N/A')}")
        print(f"{Fore.WHITE}     Location     : {geo.get('loc', 'N/A')}")
        print(f"{Fore.WHITE}     Org          : {geo.get('org', 'N/A')}")
        print(f"{Fore.WHITE}     Postal       : {geo.get('postal', 'N/A')}")
        print(f"{Fore.WHITE}     Timezone     : {geo.get('timezone', 'N/A')}")

        # IPQualityScore - Proxy/VPN/Tor check
        if IPQUALITYSCORE_KEY:
            q_url = f"https://ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_KEY}/{ip}"
            q_data = requests.get(q_url).json()
            print(f"\n{Fore.MAGENTA}[🕵️‍♂️] VPN / Proxy / TOR Detection:")
            print(f"{Fore.WHITE}     ISP          : {q_data.get('ISP', 'N/A')}")
            print(f"{Fore.WHITE}     Organization : {q_data.get('organization', 'N/A')}")
            print(f"{Fore.WHITE}     Host         : {q_data.get('host', 'N/A')}")
            print(f"{Fore.WHITE}     VPN Detected : {q_data.get('vpn', 'N/A')}")
            print(f"{Fore.WHITE}     TOR Detected : {q_data.get('tor', 'N/A')}")
            print(f"{Fore.WHITE}     Proxy        : {q_data.get('proxy', 'N/A')}")
            print(f"{Fore.WHITE}     Mobile       : {q_data.get('mobile', 'N/A')}")

        # External Lookups
        print(f"\n{Fore.BLUE}[🛡️] External Intelligence Links:")
        print(f"{Fore.BLUE}    AbuseIPDB     : https://www.abuseipdb.com/check/{ip}")
        print(f"{Fore.BLUE}    Censys        : https://search.censys.io/hosts/{ip}")
        print(f"{Fore.BLUE}    Shodan        : https://www.shodan.io/host/{ip}")
        print(f"{Fore.BLUE}    VirusTotal    : https://www.virustotal.com/gui/ip-address/{ip}")
        print(f"{Fore.BLUE}    GreyNoise     : https://www.greynoise.io/viz/ip/{ip}")
        print(f"{Fore.BLUE}    ThreatCrowd   : https://www.threatcrowd.org/ip.php?ip={ip}")
        print(f"{Fore.BLUE}    IPWhois       : https://ipwhois.app/ip/{ip}")
        print(f"{Fore.BLUE}    Talos Intel   : https://talosintelligence.com/lookup?search={ip}")
        print(f"{Fore.BLUE}    BinaryEdge    : https://app.binaryedge.io/services/query?query={ip}")
        print(f"{Fore.BLUE}    ZoomEye       : https://www.zoomeye.org/searchResult?q={ip}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}")

def main():
    ip = input(f"{Fore.CYAN}🌐 Enter IP address: {Style.RESET_ALL}").strip()
    get_ip_info(ip)

if __name__ == '__main__':
    main()

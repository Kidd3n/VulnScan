from scapy.all import ARP, Ether, srp
import manuf
import nmap

def get_oui(mac_address):
    parser = manuf.MacParser()
    oui = parser.get_manuf(mac_address)
    return oui if oui else "Desconocido"

def scan_network(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("\n[+] IP\t\t\t[+] MAC Address\t\t[+] Fabricante\n------------------------------------------------------------")
    for element in answered_list:
        ip_address = element[1].psrc
        mac_address = element[1].hwsrc
        oui = get_oui(mac_address)
        print(f"{ip_address}\t\t{mac_address}\t  {oui}")

if __name__ == "__main__":
    network_address = input("\n[?] IP de la red local (Ej: 192.168.1.0): ")
    scan_network(network_address + "/24")

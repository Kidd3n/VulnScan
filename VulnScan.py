import nmap
from scapy.all import ARP, Ether, srp
import manuf

def get_oui(mac_address):
    """Obtener el fabricante (OUI) de una dirección MAC."""
    parser = manuf.MacParser()
    oui = parser.get_manuf(mac_address)
    return oui if oui else "Desconocido"

def scan_network(network):
    """Realizar un escaneo de red para descubrir dispositivos y sus direcciones MAC."""
    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = srp(arp_request_broadcast, timeout=1, verbose=False)

        print("\n[+] Dispositivos en la red:\n")
        print("[+] IP\t\t\t[+] MAC Address\t\t[+] Fabricante\n------------------------------------------------------------")
        for sent, received in answered_list:
            print(f"{received.psrc}\t\t{received.hwsrc}\t  {get_oui(received.hwsrc)}")

        if input("\n¿Desea escanear vulnerabilidades con Nmap para los dispositivos encontrados? [y/n]: ").lower() == "y":
            nmap_scan(network)
    except Exception as e:
        print(f"Error durante el escaneo de red: {e}")

def nmap_scan(network):
    """Realizar un escaneo de vulnerabilidades en la red utilizando Nmap."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-T5 --script vuln')

        print("\n[+] Resultados del escaneo de vulnerabilidades con Nmap:\n")
        for host in nm.all_hosts():
            print("\n[+] IP: %s" % host)
            print("[+] Nombre: %s" % nm[host].hostname())
            print("[+] Resultado del escaneo de vulnerabilidades:")
            for proto in nm[host].all_protocols():
                print("Protocolo : %s" % proto)
                ports = nm[host][proto].keys()
                for port in ports:
                    print("Puerto : %s\t Estado : %s" % (port, nm[host][proto][port]['state']))
                    script_output = nm[host][proto][port].get('scripts', {})
                    if script_output:
                        for script_name, script_info in script_output.items():
                            print("Nombre del script : %s\t Resultado : %s" % (script_name, script_info))
                    else:
                        print("No se encontraron scripts de vulnerabilidad para este puerto.")
    except Exception as e:
        print(f"Error durante el escaneo de vulnerabilidades con Nmap: {e}")

if __name__ == "__main__":
    network_address = input("\n[?] IP de la red local (Ej: 192.168.1.0): ")
    scan_network(network_address + "/24")

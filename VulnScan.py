import nmap

def scan_network(network):
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')  

    for host in nm.all_hosts():
        print('[+] IP: %s' % host)
        if 'hostnames' in nm[host]:
            print('[+] Nombre: %s' % nm[host]['hostnames'][0]['name'])
        print('[+] Estado: %s' % nm[host].state())

        if 'mac' in nm[host]['addresses']:
            print('[+] Direccion MAC: %s' % nm[host]['addresses']['mac'])
        if 'vendor' in nm[host]:
            vendors = nm[host]['vendor']
            if vendors:
                vendor_name = list(vendors.values())[0]
                print('[+] Fabricante: %s' % vendor_name)

        print('')

if __name__ == "__main__":
    network_address = input("\n[?] IP de la red local (Ej: 192.168.1.0): ")
    scan_network(network_address + '/24')

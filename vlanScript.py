from scapy.all import ARP, Ether, srp

def scan_vlan(ip_range):
    # Crează un pachet ARP request pentru toate IP-urile din range
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Adresă broadcast
    packet = ether / arp

    print(f"Sending ARP requests to {ip_range}...")
    # Trimite pachetul și primește răspunsurile
    result = srp(packet, timeout=5, verbose=1)[0]

    # Lista de dispozitive active
    devices = []
    for sent, received in result:
        print(f"Received response from {received.psrc} with MAC {received.hwsrc}")
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    # Specific range-ul de IP-uri al VLAN-ului
    ip_range = "10.8.11.8/24"

    print(f"Scanning VLAN in range {ip_range}...")
    active_devices = scan_vlan(ip_range)

    if active_devices:
        print("Active devices found:")
        for device in active_devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("No active devices found.")

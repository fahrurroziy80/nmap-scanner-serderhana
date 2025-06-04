import nmap

scanner = nmap.PortScanner()
target = 'scanme.nmap.org'  # bisa ganti dengan IP sendiri

print(f"Scanning {target}...")
scanner.scan(hosts=target, arguments='-sS -p 22-443')

for host in scanner.all_hosts():
    print(f"\n[+] Host: {host} ({scanner[host].hostname()})")
    print(f"    Status: {scanner[host].state()}")

    for proto in scanner[host].all_protocols():
        print(f"    Protocol: {proto}")
        ports = scanner[host][proto].keys()
        for port in sorted(ports):
            state = scanner[host][proto][port]['state']
            print(f"      Port {port}: {state}")

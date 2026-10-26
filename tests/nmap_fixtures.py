"""Canned `nmap -oX -` documents for mocked-subprocess tests."""

def nmap_xml(ports=(("tcp", 22, "open", "ssh", "OpenSSH", "7.2p2"), ("tcp", 80, "open", "http", "Apache httpd", "2.4.49"),
                    ("tcp", 25, "closed", "smtp", None, None), ("tcp", 443, "filtered", "https", None, None)),
             host="127.0.0.1", up=True, elapsed="1.52", extra_closed=995):
    rows = ""
    for proto, num, state, name, product, version in ports:
        svc = f'<service name="{name}"' + (f' product="{product}"' if product else "") + (f' version="{version}"' if version else "") + ' method="probed" conf="10"/>'
        rows += f'<port protocol="{proto}" portid="{num}"><state state="{state}" reason="syn-ack"/>{svc}</port>'
    host_xml = (f'<host><status state="up" reason="syn-ack"/><address addr="{host}" addrtype="ipv4"/><ports>'
                f'<extraports state="closed" count="{extra_closed}"/>{rows}</ports></host>') if up else \
               f'<host><status state="down" reason="no-response"/><address addr="{host}" addrtype="ipv4"/></host>'
    return ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="nmap -oX -" version="7.94">'
            f'{host_xml}<runstats><finished time="1" elapsed="{elapsed}" exit="success"/>'
            f'<hosts up="{1 if up else 0}" down="{0 if up else 1}" total="1"/></runstats></nmaprun>')

#!/usr/bin/python

import ipaddress
import argparse
import socket
import sys
from  datetime import datetime, timezone
from urllib.request import ssl, socket
import os
import concurrent.futures
import OpenSSL

sslports = [ 443, 636 ]
retry = 5
delay = 10
timeout = 3

def get_cert_details(hostname: str, port: str) -> int:
    """
    Get number of days before an TLS/SSL of a domain expired
    """
    context = ssl.SSLContext()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname = hostname) as ssock:
            certificate = ssock.getpeercert(True)
            cert = ssl.DER_cert_to_PEM_cert(certificate)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            cert_expires = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%S%z')
            num_days = (cert_expires - datetime.now(timezone.utc)).days
            cert_issuer = x509.get_issuer().O
            cert_subject = x509.get_subject().CN
            if (args.csv):  print(f'{hostname},{port},{cert_subject},{cert_issuer},{num_days}')
            else: print(f'{hostname} {port}: {cert_subject} cert from {cert_issuer} expires in {num_days} day(s)')
            return num_days

def ipTest(ip):
   response = os.system("ping -c 1 -w 1 " + ip + " >/dev/null")
   if response == 0:
        if (args.verbose): print(ip + " is up")
        for port in sslports:
           if isOpen(ip, port): 
               if (args.verbose): print(ip, ":", port,"  Open!")
               get_cert_details(ip, port)
           else:
              if (args.verbose): print(ip, ":", port, "  Closed!")

   else:
       if (args.verbose):
          print(ip + " is down")

def isOpen(ip, port):
    location=(str(ip),port)
    try:
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       s.settimeout(1)
       result = s.connect_ex(location)
       if result == 0:
          return True
       else:
          return False
       s.close()
    except KeyboardInterrupt:
       print("You pressed Ctrl+C")
       sys.exit()
    except socket.gaierror:
       return False
       sys.exit()
    except socket.error:
       return False
       sys.exit()

parser = argparse.ArgumentParser()
parser.add_argument("cidrblock", help="Block to scan in CIDR notation")
parser.add_argument("--csv", help="Output format in csv",action="store_true")
parser.add_argument("--verbose", help="Output verbose",action="store_true")
parser.add_argument("--maxWorkers", help="Number of concurrent threads to run", default=50, type=int)
args = parser.parse_args()
network=ipaddress.ip_network(args.cidrblock)
print("Working on ",args.cidrblock," for ", network.num_addresses, " addresses in total.")
with concurrent.futures.ThreadPoolExecutor(max_workers=args.maxWorkers) as executor:
   future_to_ipTest = {executor.submit(ipTest, str(ip)): ip for ip in ipaddress.IPv4Network(args.cidrblock)}
   for future in concurrent.futures.as_completed(future_to_ipTest):
       ip = future_to_ipTest[future]
       try:
           data = future.result()
       except Exception as exc:
            print('%r generated an exception: %s' % (ip, exc))
       # else:
       #    if (args.verbose): print('Return from %r' % (ip))

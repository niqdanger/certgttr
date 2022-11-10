# certgttr.py

certgttr is a python script that takes a subnet in CIDR form, scans it for open SSL ports (443 and 636 in code)
and if it finds one, shows the SSL cert information on that port.

--csv will print in CSV format for easy import into an Excel spreadsheet
--verbose prints out lots of extra output as it tests IPs and ports

currently I run it with 2>/dev/null as OpenSSL.py spits out an error

# usage

certgttr.py 10.10.10.0/24 2>/dev/null

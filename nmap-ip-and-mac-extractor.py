#!/usr/bin/python3

# 20201012 Roey Katz: parse out the IPs and MACs from .nmap files


# sample .nmap output format:
#   Nmap scan report for  (192.168.3.4)
#   Host is up (0.0001s latency). 
#   MAC Address: A1:E20:BF:A2:3E:AC (Cisco Systems)

        

import sys
import re

def parse_IP_and_MAC(lines):

    state=0 # first one
    IP_Address = ''
    MAC_Address = ''
    up = False
    state = 0

    for line in lines:
      if state==0:  
        if line.startswith("Nmap scan report for"):
            IP = line.split("Nmap scan report for")[1]
            IP_Address = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", IP)[0].strip()
            state = 1
            continue


      elif state==1:
        if line.startswith('Host is up'):
          up = True
          state = 2
          continue

      elif state==2:
        if line.startswith('MAC Address'):        
          MAC_line = line.split('MAC Address:')[1]
          _MAC_Address = re.findall(r'(?:[0-9a-fA-F]:?){12}', MAC_line)
          MAC_Address = _MAC_Address[0]

          res = IP_Address + ", " + MAC_Address
          print(res)
          
          # since this was the last line, of three, so make other vars available
          MAC_Address = '' # clear out MAC_Address
          up = False # reset host up flag to False
          state = 0 # reset state back to 0
          continue

if __name__=="__main__":
    if len(sys.argv)==0:
        print("Usage: parse-nmap-IPs-and-MACS.py file1.nmap file2.nmap ... fileN.nmap")
        sys.exit(1)
        
    fnames=sys.argv[1:]
        
    for fname in fnames:
        parse_IP_and_MAC(open(fname).readlines())

   


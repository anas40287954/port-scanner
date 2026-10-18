# import requests

# target = "http://192.168.100.1:7547"

# # TR-069 uses SOAP over HTTP (POST)
# soap_payload = '''<?xml version="1.0"?>
# <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
#   <soap:Body>
#     <cwmp:Inform xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
#       <DeviceId>
#         <Manufacturer>Test</Manufacturer>
#         <OUI>000000</OUI>
#         <ProductClass>Router</ProductClass>
#         <SerialNumber>12345</SerialNumber>
#       </DeviceId>
#       <Event>
#         <EventCode>0 BOOTSTRAP</EventCode>
#       </Event>
#       <MaxEnvelopes>1</MaxEnvelopes>
#       <CurrentTime>0</CurrentTime>
#       <RetryCount>0</RetryCount>
#       <ParameterList></ParameterList>
#     </cwmp:Inform>
#   </soap:Body>
# </soap:Envelope>'''

# headers = {
#     'Content-Type': 'text/xml',
#     'SOAPAction': ''
# }

# try:
#     r = requests.post(target, data=soap_payload, headers=headers, timeout=3)
#     print(f"[+] Status: {r.status_code}")
#     print(f"[+] Response:\n{r.text[:1000]}")
# except Exception as e:
#     print(f"[-] Error: {e}")








# import socket
# import time

# target = "192.168.100.1"
# port = 7547

# # TCP fingerprint — what does the banner say?
# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# sock.settimeout(2)
# try:
#     sock.connect((target, port))
#     sock.send(b"GET / HTTP/1.0\r\n\r\n")
#     banner = sock.recv(1024)
#     print(f"[+] Banner:\n{banner.decode('utf-8', errors='ignore')}")
# except Exception as e:
#     print(f"[-] {e}")
# finally:
#     sock.close()













import socket
import base64

def send_cwmp_with_auth(target, port=7547, username="admin", password="admin"):
    """Send CWMP with HTTP Basic Auth."""
    
    soap_body = b'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <soap:Body>
    <cwmp:Inform>
      <DeviceId>
        <Manufacturer>TOP-Fiber</Manufacturer>
        <OUI>000000</OUI>
        <ProductClass>Router</ProductClass>
        <SerialNumber>123456789</SerialNumber>
      </DeviceId>
      <Event>
        <EventCode>0 BOOTSTRAP</EventCode>
      </Event>
      <MaxEnvelopes>1</MaxEnvelopes>
      <CurrentTime>0</CurrentTime>
      <RetryCount>0</RetryCount>
      <ParameterList/>
    </cwmp:Inform>
  </soap:Body>
</soap:Envelope>'''

    # Basic auth header
    auth_str = base64.b64encode(f"{username}:{password}".encode()).decode()
    
    http_request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: 192.168.100.1:7547\r\n"
        b"Content-Type: text/xml; charset=utf-8\r\n"
        b"Content-Length: " + str(len(soap_body)).encode() + b"\r\n"
        b"Authorization: Basic " + auth_str.encode() + b"\r\n"
        b"Connection: close\r\n"
        b"SOAPAction: \"\"\r\n"
        b"\r\n" + soap_body
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    
    try:
        sock.connect((target, port))
        print(f"[*] Trying auth: {username}:{password}")
        sock.sendall(http_request)
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        resp_str = response.decode('utf-8', errors='ignore')
        print(resp_str[:500])
        
    except Exception as e:
        print(f"[-] {e}")
    finally:
        sock.close()

# Try common TOP Fiber / default creds
creds = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
]

for user, pwd in creds:
    send_cwmp_with_auth("192.168.100.1", username=user, password=pwd)
    print()
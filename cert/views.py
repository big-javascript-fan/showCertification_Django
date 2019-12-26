from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.template import loader

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
from collections import namedtuple
import concurrent.futures

import requests

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

# Create your views here.

def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def index(req):
  template = loader.get_template('cert/index.html')
  context = {}
  return HttpResponse(template.render(context, req))

def getCert(req):
  if req.method == 'GET':
    domain = req.GET.get('domain')
    try:
      request = requests.get("https://" + domain, timeout=1)
      if request.status_code == 200:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
          for hostinfo in e.map(lambda x: get_certificate(x[0], x[1]), [(domain, 443)]):
            certInfo = hostinfo
        return JsonResponse({"status": "success",  "commonname": get_common_name(certInfo.cert), "issuer": get_issuer(certInfo.cert), "notbefore": certInfo.cert.not_valid_before, "notafter": certInfo.cert.not_valid_after})
    except:
      return JsonResponse({"status": "failed"})
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.template import loader

import socket
import ssl

def index(req):
  template = loader.get_template('cert/index.html')
  context = {}
  return HttpResponse(template.render(context, req))

def getCert(req):
  if req.method == 'GET':
    domain = req.GET.get('domain')
    try:
      ctx = ssl.create_default_context()
      s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
      s.connect((domain, 443))
      cert = s.getpeercert()
    except:
      return JsonResponse({"status": "failed"})

    subject = dict(x[0] for x in cert['subject'])
    issued_to = subject['commonName']
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer['commonName']
    isused_from = cert['notBefore']
    isused_to = cert['notAfter']
    return JsonResponse({"status": "success",  "commonname": issued_to, "issuer": issued_by, "notbefore": isused_from, "notafter":isused_to})


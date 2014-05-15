import getdns
import sys


def get_dnssec_status(domain,results):
    replies_tree = results['replies_tree']
    if (not replies_tree) or (not len(replies_tree)): #or (not replies_tree[0]['answer']) or (not len(replies_tree[0]['answer'])):
        print 'Domain Not Found'
        return None
    else:
        reply = replies_tree[0]
        if reply['dnssec_status'] == getdns.GETDNS_DNSSEC_SECURE:
            return 'Verified by DNSSEC ('+domain+')'
        if reply['dnssec_status'] == getdns.GETDNS_DNSSEC_BOGUS:
            return 'Bogus DNSSEC ('+domain+')'
    if reply['dnssec_status'] == getdns.GETDNS_DNSSEC_INDETERMINATE:
    #The zone is signed, but no DS record in the parent-- so the DNS key at this stage is not signed by the parent. Not connected to the root of trust
            return 'Indeterminate DNSSEC ('+domain+')'
    if reply['dnssec_status'] == getdns.GETDNS_DNSSEC_INSECURE:
    #Not protected by DNSSEC
            return 'Unverified by DNSSEC ('+domain+')'
            return None                      

    
def request_email_auth_info(domains):
    email_info = ""
    domains = set(domains)
    for domain in domains:
        print "domain:", domain
        context = getdns.context_create()
        extensions = { 'dnssec_return_status' : 1000 }
        results = getdns.general(context, str(domain), getdns.GETDNS_RRTYPE_SOA, extensions=extensions)
        if results['status'] != getdns.GETDNS_RESPSTATUS_GOOD:
            email_info += 'Sender Domain is unknown'
        else:
            record = get_dnssec_status(domain, results)
        if email_info== "":
            email_info=record
        else:
            email_info = email_info + ', '+record
    if not email_info:
        email_info = "Unknown domain"
    print "info:", email_info
    return email_info


import BaseHTTPServer
from sys import version as python_version
from cgi import parse_header, parse_multipart
from urlparse import parse_qs

class GetHandler (BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        import urllib2, urlparse
        full_query = self.path
        print full_query
        domains = full_query.split("host=")[1]
        print domains
        domains = set(domain for domain in domains.split(",") if domain)
        email_info = request_email_auth_info(domains)
        print "results:", email_info
        self.send_response(200)
        self.send_header("Content-Length", str(len(email_info.encode("utf8"))))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(email_info.encode("utf8"))


print "launching"
def run(server_class=BaseHTTPServer.HTTPServer,
        handler_class=GetHandler):
    server_address = ('', 8085)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
    print "started"
    sys.stdout.flush()
run()
print "done"
sys.stdout.flush()









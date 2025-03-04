from bcc import BPF
from time import sleep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import socket
import os
import sys

if len(sys.argv) != 2:
    print("Usage: %s <SOCK_FILE>" % (sys.argv[0]))
    exit(1)

SOCK_FILE = sys.argv[1]

class UnixSocketRequestHandler(BaseHTTPRequestHandler):
    def load_bpf(self):
        try:
            print("load bpf program")
            b = BPF(src_file="./data/traffic.c")

            print("attach kprobe and kretprobe")
            b.attach_kprobe(event="udp_sendmsg", fn_name="kprobe__udp_sendmsg")
            b.attach_kretprobe(event="udp_sendmsg", fn_name="kretprobe__udp_sendmsg")
            b.attach_kprobe(event="udpv6_sendmsg", fn_name="kprobe__udpv6_sendmsg")
            b.attach_kretprobe(event="udpv6_sendmsg", fn_name="kretprobe__udpv6_sendmsg")
            b.attach_kretprobe(event="skb_consume_udp", fn_name="kprobe__skb_consume_udp")
            b.attach_kprobe(event="tcp_sendmsg", fn_name="kprobe__tcp_sendmsg")
            b.attach_kretprobe(event="tcp_sendmsg", fn_name="kretprobe__tcp_sendmsg")
            b.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="kprobe__tcp_cleanup_rbuf")
            b.attach_kprobe(event="ip_output", fn_name="kprobe__ip_output")
            b.attach_kprobe(event="ip6_output", fn_name="kprobe__ip6_output")

            print("load bpf program success")
            UnixSocketRequestHandler.bpf = b

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write("success")
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e))

    def get_flow(self):
        try:
            flow = [0 for i in range(14)]
            for k, v in self.bpf["network_flow_map"].items():
                flow[int(k.value)] = sum(v)
            body = '[' + ','.join(map(str, flow)) + ']'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e))

    def do_GET(self):
        if self.path == "/load":
            self.load_bpf()
        else:
            self.get_flow()

    def log_message(self, format, *args):
        pass

class UnixSocketHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        if os.path.exists(self.server_address):
            os.unlink(self.server_address)
        HTTPServer.server_bind(self)

try:
    print("run http server")
    httpd = UnixSocketHTTPServer(SOCK_FILE, UnixSocketRequestHandler)
    httpd.serve_forever()
except KeyboardInterrupt:
    print("stop server")
    exit(0)
except Exception as e:
    print("error: %s" % str(e))
    exit(1)

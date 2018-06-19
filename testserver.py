import json
import BaseHTTPServer
import traceback
import collections

from xmltodict import xmltodict

JSON_PATTERN = json.loads("""
{
    "a" : { "q" : 1},
    "b" : [ 1, 2, 3],
    "c" : "d"
}
""")

#Test vector:
"""
{
    "a" : { "q" : 1, "w": 3},
    "b" : [ 1,2, 3,4,5,6],
    "c" : "d", "e":{"1":4, "8":7}
}
"""

XML_PATTERN = xmltodict.parse("""
<root>
    <element name="example">
        <property_one value="value1"/>
        <property_two/>
        <property_three>
            <subelement needed="value">Action</subelement>
        </property_three>
    </element>
</root>
""")
RESP = """HTTP/1.1 200 OK\r\nServer: nginx/1.8.1\r\nDate: Tue, 19 Jun 2018 11:24:36 GMT\r\nContent-Length: 3\r\n\r\n"""
def check_contains (dict_, pattern):
    print "pattern", json.dumps(pattern, indent=2)
    print "dict", json.dumps(dict_, indent=2)
    if type(dict_) == list:
        if type(pattern) != list:
            return False
        dict_ = dict(enumerate(dict_))
        pattern = dict(enumerate(pattern))
    for key in pattern.keys():
        if not key in dict_:
            print key, "not in dict"
            return False
        val_d = dict_[key]
        val_p = pattern[key]
        if not type(val_d) == type(val_p):
            print key, 'type mismatch'
            return False
        if type(val_d) not in [dict, collections.OrderedDict, list]:
            if val_d != val_p:
                print key, 'value mismatch'
                return False
            else:
                continue
        if not check_contains(val_d, val_p):
            return False
    return True

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        data = self.rfile.read(int(self.headers.getheader('content-length')))
        try:
            if self.path == '/json':
                d = json.loads(data)
                if check_contains(d, JSON_PATTERN):
                    self.wfile.write(RESP+"OK!")
                else:
                    self.wfile.write(RESP+"NOP")
                self.wfile.flush()
            if self.path == '/xml':
                d = xmltodict.parse(data)
                if check_contains(d, XML_PATTERN):
                    self.wfile.write(RESP+"OK!")
                else:
                    self.wfile.write(RESP+"NOP")
                self.wfile.flush()

        except Exception as e:
            self.wfile.write(RESP+"WAT")
            traceback.print_exc()
def run(server_class=BaseHTTPServer.HTTPServer,
        handler_class=MyHandler):
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

run()

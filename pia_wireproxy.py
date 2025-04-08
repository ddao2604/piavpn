from http import HTTPStatus
import http.server
from multiprocessing import Process
import signal
import socketserver
from typing import Tuple
import requests
import json
import subprocess
import os
import sys
import time


from config import PIA_USER, PIA_PASS, PIA_LOCS, PIA_PORT_START, PIA_HEL_START, SOCKS_USER, SOCKS_PASS, HEALTH_SLEEP
from key import gen_wg_keys

servers = []
ip = ""
class Proxy():
    def __init__(self) -> None:
        self.ser = []
            
    def get_wg_regions(self):
        regions = {}
        serverlist_url = "https://serverlist.piaservers.net/vpninfo/servers/v6"

        r = requests.get(serverlist_url)
        r_no_cert = r.text.partition("\n")[0]
        server_list = json.loads(r_no_cert)

        for region in server_list["regions"]:
            if region["country"] not in regions:
                regions[region["country"]] = []

            if not region["offline"]:
                for ip in region["servers"]["wg"]:
                    r = {
                        "ip": ip["ip"],
                        "cn": ip["cn"],
                        "dns": region["dns"]
                    }
                    regions[region["country"]].append(r)

        return regions

    def get_wg_json(self,region, token, pk):
        baseurl = "https://" + region["ip"] + ":1337"
        endpoint = "/addKey"

        params = {
            "pt": token,
            "pubkey": pk
        }
        
        headers = {
            "Host": region["dns"]
        }

        r = requests.get(baseurl + endpoint, headers=headers, params=params, verify=False)
        return r.json()

    def get_wg_config(self,region, token, socks_port):
        sk, pk = gen_wg_keys()

        j = self.get_wg_json(region, token, pk)

        wg_file_str = f"""
        [Interface]
        Address = {j["peer_ip"]}/32
        PrivateKey = {sk}
        CheckAlive = 1.1.1.1
        CheckAliveInterval = 25

        [Peer]
        PersistentKeepalive = 25
        PublicKey = {j["server_key"]}
        AllowedIPs = 0.0.0.0/0
        Endpoint = {j["server_ip"]}:{j["server_port"]}

        [Socks5]
        BindAddress = 0.0.0.0:{socks_port}
        Username = {SOCKS_USER}
        Password = {SOCKS_PASS}
        """

        return wg_file_str

    def get_pia_token(self):
        token_url = "https://www.privateinternetaccess.com/api/client/v2/token"

        data = {
            "username": PIA_USER,
            "password": PIA_PASS
        }

        r = requests.post(token_url, data=data)
        j = r.json()

        return j["token"]

    def start_wireproxy_process(self,cfg_filename, healthport):
        haddr = f"127.0.0.1:{healthport}"
        with open(os.devnull, 'w') as fp:
            p = subprocess.Popen(["./wireproxy", "--config", cfg_filename, "--info", haddr,"-s"], stdout=fp)

            return p.pid

    def start_wireproxy(self,token, s):
        cfg_str = self.get_wg_config(s["region"], token, s["port"])

        cfg_dir = "wg"
        if not os.path.exists(cfg_dir):
            os.makedirs(cfg_dir)

        regname = s["region"]["cn"]
        cfg_filename = f"{cfg_dir}/{regname}.conf"

        with open(cfg_filename, "w") as f:
            f.write(cfg_str)
            #print(f"wrote config to {cfg_filename}")
        
        return self.start_wireproxy_process(cfg_filename, s["healthport"])

    def check_health(self):
        # give time for wireproxy to start
        time.sleep(HEALTH_SLEEP)

        while True:
            
            for srv in servers:
                a = f"{srv['loc']} {srv['port']}"
                #print(a)
                url = f"http://127.0.0.1:{srv['healthport']}"
                endpoint = "/readyz"

                r = requests.get(url + endpoint)
                if r.status_code != 200:
                    print("PROXY DIE")
                    os.kill(srv['proc'], signal.SIGKILL)
                    srv["proc"] = self.start_wireproxy(srv["token"], srv)
                    #return False

                time.sleep(HEALTH_SLEEP)


    def main(self):
        regions = self.get_wg_regions()
        token = self.get_pia_token()

        #n_servers = len(PIA_LOCS)


        #for i in range(0, n_servers):

            #s = {
            #    "loc": PIA_LOCS[i],
            #    "port": PIA_PORT_START + i,
            #    "http": PIA_HTTP_START + i,
            #    "healthport": PIA_HEL_START - 1 - i,
            #    "region": regions[PIA_LOCS[i]][0],
            #}

            #s["proc"] = start_wireproxy(token, s)
            #servers.append(s)
        j = 1
  
   
        #for k in regions:
            #print(k)
        for i in regions[PIA_LOCS]:

            s = {
                "loc": regions[PIA_LOCS],
                "port": PIA_PORT_START + j,
      
                "healthport": PIA_HEL_START + j,
                "region": i,
                "token":token,
            }
            j += 1
        
            s["proc"] = self.start_wireproxy(token, s)
            servers.append(s)
        with open('data.json', 'w') as filehandle:
            json.dump(servers, filehandle)

        self.check_health()
    
        #sys.exit(1)

class Handler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, request: bytes, client_address: Tuple[str, int], server: socketserver.BaseServer):
        super().__init__(request, client_address, server)

    @property
    def api_response(self):
        
        ret = f"       RESET PROXY http://{ip}:4545/reset?[PORT]\n"
        ret += f"       LIST SOCKS5\n"
        for i in servers:
            a = f"       socks5://admin:admin@{ip}:{i['port']}\n"
            ret += a
        
        for i in servers:
          
            a = f"       {ip}:{i['port']}:admin:admin\n"
            ret += a
    
        return ret.encode()

    def do_GET(self):
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            if self.path == '/':
               
                self.wfile.write(bytes(self.api_response))
            if "reset" in self.path:
                a = self.path.split("?")

                portreset = a[1]
                print(portreset)
                rt = self.reset_proxy(portreset)
                if not rt:
                    
                    self.wfile.write(bytes("FALSE".encode()))
                else:
                    self.wfile.write(bytes("TRUE".encode()))   

        except Exception as e:
            print(e)

    def start_wireproxy_process(self,cfg_filename, healthport):
        haddr = f"127.0.0.1:{healthport}"
        with open(os.devnull, 'w') as fp:
            p = subprocess.Popen(["./wireproxy", "--config", cfg_filename, "--info", haddr,"-s"], stdout=fp)

            return p.pid
    
    def get_wg_config(self,region, token, socks_port,http_port):
        sk, pk = gen_wg_keys()

        j = self.get_wg_json(region, token, pk)

        wg_file_str = f"""
        [Interface]
        Address = {j["peer_ip"]}/32
        PrivateKey = {sk}
        CheckAlive = 1.1.1.1
        CheckAliveInterval = 25

        [Peer]
        PersistentKeepalive = 25
        PublicKey = {j["server_key"]}
        AllowedIPs = 0.0.0.0/0
        Endpoint = {j["server_ip"]}:{j["server_port"]}

        [Socks5]
        BindAddress = 0.0.0.0:{socks_port}
        Username = {SOCKS_USER}
        Password = {SOCKS_PASS}

        [http]
        BindAddress = 0.0.0.0:{http_port}
        Username = {SOCKS_USER}
        Password = {SOCKS_PASS}
        """

        return wg_file_str
    
    def get_wg_json(self,region, token, pk):
        baseurl = "https://" + region["ip"] + ":1337"
        endpoint = "/addKey"

        params = {
            "pt": token,
            "pubkey": pk
        }
        
        headers = {
            "Host": region["dns"]
        }

        r = requests.get(baseurl + endpoint, headers=headers, params=params, verify=False)
        return r.json()
    
    def get_pia_token(self):
        token_url = "https://www.privateinternetaccess.com/api/client/v2/token"

        data = {
            "username": PIA_USER,
            "password": PIA_PASS
        }

        r = requests.post(token_url, data=data)
        j = r.json()

        return j["token"]
    
    def reset_proxy(self,port):
        try:
            for i in servers:
                if i['port'] == int(port):
                    token = self.get_pia_token()
                    cfg_str = self.get_wg_config(i["region"], token, i["port"],i["http"])

                    cfg_dir = "wg"
                    if not os.path.exists(cfg_dir):
                        os.makedirs(cfg_dir)

                    regname = i["region"]["cn"]
                    cfg_filename = f"{cfg_dir}/{regname}.conf"

                    with open(cfg_filename, "w") as f:
                        f.write(cfg_str)
                        #print(f"wrote config to {cfg_filename}")
                    os.kill(i['proc'], signal.SIGKILL)

                    i['proc'] = self.start_wireproxy_process(cfg_filename, i["healthport"])
                    with open('data.json', 'w') as filehandle:
                        json.dump(servers, filehandle)
                    return True
        except Exception as e:
            print(f"catch {e}")
            return False

if __name__ == "__main__":  
    try:    
        #ip = requests.get('https://api.ipify.org').content.decode('utf8')
  
        bot = Proxy()
        bot.main()
        #PORT = 4545
        #my_server = socketserver.TCPServer(("0.0.0.0", PORT), Handler)
        #my_server.serve_forever()
    except KeyboardInterrupt:
        print("[ EXIT ]")
        #my_server.shutdown()
        os.system("killall -SIGTERM wireproxy")


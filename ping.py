import platform
import sys
import subprocess
import time
import re
from concurrent.futures import ThreadPoolExecutor


def get_os():
    ''''' 
    get platform info
    '''
    os = platform.system()
    if os == "Windows":
        return "n"
    else:
        return "c"


def parse_num(num):
    if len(num) ==2:
       return range(int(num[0]), int(num[1]))
    else:
       return [int(num[0])]


def parse_ip(*ip_str):
    ip_list = []
    r = '(?:(\d{1,3}(\-\d{1,3})?)\.){3}(\d{1,3}(\-\d{1,3})?)'
    for ip in ip_str:
        try:
             if re.match(r,ip) is None:
                raise ValueError("Invalid format {}".format(ip))
        except ValueError as e:
            print(e)
            sys.exit(1)
        s =(n.split('-') for n in ip.split('.'))
        for n1 in parse_num(next(s)):
            for n2 in parse_num(next(s)):
                for n3 in parse_num(next(s)):
                    for n4 in parse_num(next(s)):
                        ip_list.append("{}.{}.{}.{}".format(n1,n2,n3,n4))

    return ip_list


class Ping():
    def __init__(self, ip):
        self.ip = ip
        self._result = False

    def run(self):
        cmd = ["ping", "-{op}".format(op=get_os()),
               "1", self.ip]
        sp = subprocess.Popen(" ".join(cmd), stdout=subprocess.PIPE)
        sp.wait()
        output = sp.stdout.readlines()
        for line in list(output):
            if str(line).upper().find("TTL") >= 0:
                print("[{}] is up".format(self.ip))
                self._result = True

    def get_result(self):
        return self._result


def find_ip(ip_list):
    ''' 
      scan all ip address
    '''
    pl = []
    pool = ThreadPoolExecutor(128)

    r = '((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)'
    for ip in ip_list:
        try:
           if not re.match(r,ip):
                raise ValueError("Invalid ip format {}".format(ip))
        except ValueError as e:
            print(e)
            continue
        p = Ping(ip)
        pl.append(p)
        pool.submit(p.run)
    
    pool.shutdown()

    ip_list = []
    for p in pl:
        if p.get_result():
            ip_list.append(p.ip)
    return ip_list


if __name__ == '__main__':
    print("start time %s" % time.ctime())
    commandargs = sys.argv[1:]
    args = "".join(commandargs)
    if not args:
        args = "192.168.56.1-254"
    ip_list = parse_ip(args)
    find_ip(ip_list)
    print("end time %s" % time.ctime())

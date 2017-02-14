#!usr/bin/python

import sys
import os
import json
import nmap
from pssh import ParallelSSHClient, utils
from gevent import joinall
from pprint import pprint


USAGE = """error
"""


def main(args):
    args = parseJson()
    for params in args:
        hosts = execNmap(**params)
        params['hosts'] = hosts
        execPssh(**params)

def parseJson(file='pssh_test.json'):
    with open(file) as f:
        js = json.load(f)
    return js['args']

def execNmap(**args):
    nm = nmap.PortScanner()
    hosts=args['hosts']
    command=args['nmap_command']

    nm.scan(hosts=hosts,arguments=command)
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    hosts = []
    for host, status in hosts_list:
        print('{0} is {1}'.format(host,status))
        if status == 'up':
            hosts.append(host)
    return hosts

def execPssh(**args):
    hosts = args['hosts']
    port = args['ssh_port']
    user = args['ssh_user']
    passwd = args['ssh_passwd']
    command = args['ssh_command']
    scp_local_to_remote = args['scp_local_to_remote']
    scp_remote_to_local = args['scp_remote_to_local']

    psshclient = ParallelSSHClient(hosts=hosts,port=ssh_port)
    if ssh_command:
        utils.enable_host_logger()
        if isinstance(command,list):
            for cmd in command:
                output = psshclient.run_command(cmd)
        else:
            output = psshclient.run_command(command)
    psshclient.pool.join(output)

    if scp_local_to_remote:
        utils.enable_logger(utils.logger)
        if isinstance(scp_local_to_remote,list):
            for l2r in scp_local_to_remote:
                greenlets=psshclient.copy_file(l2r['local'],l2r['remote'])
        else:
            psshclient.copy_file(scp_local_to_remote['local'],scp_local_to_remote['remote'])
    joinall(greenlets,raise_error=True)
        
    if scp_remote_to_local:
        utils.enable_logger(utils.logger)
        if isinstance(scp_remote_to_local,list):
            for r2l in scp_remote_to_local:
                psshclient.copy_remote_file(l2r['remote'],l2r['local'])
        else:
            psshclient.copy_remote_file(scp_remote_to_local['remote'],scp_remote_to_local['local'])
    joinall(greenlets,raise_error=True)
    

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


#! python2
"""
exec script
"""
from __future__ import print_function

import json
import os
import sys

import nmap
from gevent import joinall
from pssh import ParallelSSHClient, utils
from pssh.exceptions import (AuthenticationException, ConnectionErrorException,
                             UnknownHostException)
import paramiko

def main(argv):
    """
        main
    """
    if not argv:
        argv.append('pssh.json')
    args = parse(argv[0])
    for index, params in enumerate(args):
        print("start task [{0}]".format(index+1))
        params['hosts'] = exec_nmap(**params)
        exec_pssh(**params)


def parse(file):
    """
        parsing json configurtion
    """
    try:
        with open(file) as config_file:
            config_json = json.load(config_file)
    except(IOError, ValueError) as error:
        print(error)
        sys.exit(1)
    return config_json['args']


def exec_nmap(**args):
    """
        executing nmap to scan ip
    """
    nmap_scan = nmap.PortScanner()
    hosts = args['hosts']
    command = args['nmap_command']

    nmap_scan.scan(hosts=hosts, arguments=command)
    hosts_list = [(x, nmap_scan[x]['status']['state'])
                  for x in nmap_scan.all_hosts()]
    hosts = []
    for host, status in hosts_list:
        print('{0} is {1}'.format(host, status))
        if status == 'up':
            hosts.append(host)
    return hosts


def exec_pssh(**args):
    """
        executing parallel-ssh process
    """
    hosts = args['hosts']

    if not hosts:
        print("no host is up")
        return
    args['pkey'] = verify_pkey(args['pkey'])
    args['proxy_pkey'] = verify_pkey(args['pkey'])

    commands_before = args['ssh_commands_before']
    commands_after = args['ssh_commands_after']
    file_local_to_remote = args['file_local_to_remote']
    file_remote_to_local = args['file_remote_to_local']

    del args['nmap_command']
    del args['ssh_commands_before']
    del args['ssh_commands_after']
    del args['file_local_to_remote']
    del args['file_remote_to_local']

    psshclient = ParallelSSHClient(**args)
    utils.enable_logger(utils.logger)

    exec_ssh_cmd(psshclient, commands_before)
    exec_scpfuc(file_local_to_remote, psshclient.copy_file)
    exec_scpfuc(file_remote_to_local, psshclient.copy_remote_file)
    exec_ssh_cmd(psshclient, commands_after)

    del psshclient


def exec_ssh_cmd(client, cmds):
    """
        executing ssh command
    """
    def exec_per_cmd(cmd):
        """
            executing per command
        """
        if not cmd:
            return
        try:
            output = client.run_command(cmd)
        except (AuthenticationException, UnknownHostException, ConnectionErrorException):
            pass
        for host in output:
            while True:
                out = next(output[host]['stdout'], None)
                err = next(output[host]['stderr'], None)
                if (out is None) and (err is None):
                    break
        client.join(output)
    if isinstance(cmds, list):
        for cmd in cmds:
            exec_per_cmd(cmd)
    else:
        exec_per_cmd(cmds)


def exec_scpfuc(files, scp_fuc):
    """
        utils function
    """
    def exec_per_file(files):
        """
            executing fuction
        """
        if not files:
            return
        local = os.path.abspath(files['local'])
        remote = files['remote']
        greenlets = scp_fuc(local_file=local, remote_file=remote, recurse=True)
        try:
            joinall(greenlets, raise_error=True)
        except(IOError, OSError):
            pass
        for greenlet in greenlets:
            if greenlet.exception:
                print(greenlet, greenlet.exception)

    if isinstance(files, list):
        for afile in files:
            exec_per_file(afile)
    else:
        exec_per_file(files)


def verify_pkey(pkeyfile):
    """
        return pkey object
    """
    if pkeyfile:
        pkeyfile = os.path.abspath(pkeyfile)
        try:
            pkey = paramiko.RSAKey.from_private_key_file(pkeyfile)
        except(IOError, paramiko.PasswordRequiredException, paramiko.SSHException) as error:
            print("[Reson]:", error)
            return None
        return pkey


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

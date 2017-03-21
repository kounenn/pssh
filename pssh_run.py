import json
import os
import sys
import logging
import socket
import time

from gevent import joinall
from pssh import ParallelSSHClient, utils
from pssh.exceptions import (
    AuthenticationException, ConnectionErrorException, UnknownHostException)
import paramiko

from ping import parse_ip, find_ip

CONFIRM = False


class SSHargs():
    def __init__(self, _dict={}):
        self._dict = _dict

    def get(self, k, t):
        v = self._dict.get(k)
        if v is None:
            return t()
        elif isinstance(v, t):
            return v
        else:
            raise TypeError(
                "Invaild args format, {} should be {}".format(v, t))


def _confirm():
    if CONFIRM:
        if input('confirm operation, enter any key to continue, enter n/N to exit: ').strip().upper() == 'N':
            sys.exit(2)


def parse_json(file):
    """
        parsing json configurtion
    """
    try:
        with open(file) as config_file:
            config = json.load(config_file)
    except IOError as e:
        utils.logger.error(e)
        raise
    except json.JSONDecodeError:
        utils.logger.error(
            "Invaild json format, Please check {}".format(os.path.basename(file)))
        raise

    return config


def exec_pssh(args, ping_hosts):
    """
    exec parallel-ssh process
    """

    try:
        if not args:
            print(args)
            raise ValueError('args is empty !')
        ssh_args = SSHargs(args)

        client = ssh_args.get('client', dict)
        hosts = client.get('hosts',[])
        if not isinstance(hosts,list):
            raise TypeError
        hosts.extend(ping_hosts)
        client['hosts'] = hosts

        if not hosts:
            raise ValueError('host list is empty !')

        if 'pkey' in client:
            client['pkey'] = verify_pkey(client['pkey'])
        if 'proxy_pkey' in client:
            client['proxy_pkey'] = verify_pkey(client['proxy_pkey'])
        
        client['channel_timeout'] = client.get('channel_timeout',10) 

        commands_before = ssh_args.get('commands_before', list)
        commands_after = ssh_args.get('commands_after', list)
        file_local_to_remote = ssh_args.get('file_local_to_remote', list)
        file_remote_to_local = ssh_args.get('file_remote_to_local', list)

    except(TypeError, ValueError) as e:
        utils.logger.error(e)
        raise

    psshclient = ParallelSSHClient(**client)

    for cmd in commands_before:
        _confirm()
        exec_ssh_cmd(psshclient, cmd)

    for f in file_local_to_remote:
        _confirm()
        exec_scpfuc(f, psshclient.copy_file)

    for f in file_remote_to_local:
        _confirm()
        exec_scpfuc(f, psshclient.copy_remote_file)

    for cmd in commands_after:
        _confirm()
        exec_ssh_cmd(psshclient, cmd)

    del psshclient

    return True


def exec_ssh_cmd(client, cmd):
    """
    exec ssh command
    """
    try:
        utils.logger.info('run [{}]'.format(cmd))
        output = client.run_command(cmd)
    except (AuthenticationException, UnknownHostException, ConnectionErrorException) as e:
        utils.logger.warning(e)
        return False

    for host in output:
        try:
            for line in output[host].stdout:
                pass
        except socket.timeout:
            utils.logger.warning("run [{}] on [{}] raise an TimeoutError".format(cmd,host))
            continue
    return True


def exec_scpfuc(files, scp_fuc):
    """
    exec function for files
    """
    local = files.get('local',None)
    remote = files.get('remote',None)

    if local and remote:
        local = os.path.abspath(local)     
    else:
        return False

    greenlets = scp_fuc(local_file=local, remote_file=remote, recurse=True)

    try:
        joinall(greenlets, raise_error=True)
    except(IOError, OSError, TypeError) as e:
        utils.logger.warning("operation files fail\n", e)
        return False

    return True


def verify_pkey(pkeyfile):
    """
    return pkey object
    """
    if pkeyfile:
        pkeyfile = os.path.abspath(pkeyfile)
        try:
            pkey = paramiko.RSAKey.from_private_key_file(pkeyfile)
        except(IOError, paramiko.PasswordRequiredException, paramiko.SSHException) as error:
            utils.logger.warning(('[Reson]:', error))
            return None
        return pkey


def main():
    """
        main
    """
    config = parse_json('config.json')
    logging.basicConfig(level = logging.INFO,filename='log.log', filemode='w')
    utils.enable_logger(utils.logger)

    global CONFIRM 
    CONFIRM = config.get('confirm',False)

    for cf in config.get('tasks',[]):
        config = parse_json(cf)
        ip_list = []
        
        timer = config.get('timer',0)
        for n in range(timer):
            print('wating {:04}s to run task [{}]\r'.format(timer-n,cf),end='')
            time.sleep(1)
        else:
            print()
        for ip_str in config.get('ping',[]):
            ip_list.extend(find_ip(parse_ip(ip_str)))
        if exec_pssh(config, ip_list):
            utils.logger.info("[{}] succeed !".format(cf))
        else:
            utils.logger.warning("[{}] failed !")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        utils.logger.error(e,sys.int_info)
        utils.logger.error("Exec failure !")
    input("press Enter to exit")
    sys.exit(0)
    

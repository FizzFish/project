#!/usr/bin/env python2
import os
import re
from common import Logger, simple

tcp_list = []
logger = Logger(__name__).getlogger()

class ProcArg:
    def __init__(self, arg):
        self.simple = simple(arg)
        self.fuzz_flag = False
        self.absolute = arg
    def set_abs(self, absolute):
        self.absolute = absolute
    def set_fuzz_flag(self):
        self.fuzz_flag = True

class TcpEntry:
    def __init__(self, la, lp, ra, rp, stat, inode):
        self.ra, self.la = ra, la
        self.rp = int(rp, 16)
        self.lp = int(lp, 16)
        self.inode = int(inode)
        self.status = int(stat, 16)

def get_tcp_list():
    with open('/proc/net/tcp', 'r') as fd:
        lines = fd.readlines()

    pattern = re.compile("^\\s*([0-9]+): ([0-9A-F]+):(....) ([0-9A-F]+):(....) (..) ([^ ]+ ){3}\\s*([0-9]+)\\s+[0-9]+\\s+([0-9]+).*$")
    global tcp_list
    tcp_list = []
    for line in lines[1:]:
        m = pattern.match(line)
        tcp = TcpEntry(m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(9))
        tcp_list.append(tcp)
        

class Process:
    def __init__(self, pid):
        self.pid = pid
        self.exe = os.readlink('/proc/{}/exe'.format(pid))

    def is_sys_proc(self):
        # 1. check pid or pid <= 2
        # 2. check usr in whitelist user
        pass
    def analyse_argument(self):
        cmd = "cat /proc/{}/cmdline | xargs -0 echo".format(self.pid)
        result = os.popen(cmd).read()[:-1]
        cmds = result.split(' ')
        self.argmap = {}
        for cmd in cmds[1:]:
            arg = ProcArg(cmd)
            self.argmap[arg.simple] = arg

    def gen_fuzz_args(self):
        ret = []
        for arg in self.argmap.values():
            if arg.fuzz_flag:
                ret.append("@@")
            else: 
                ret.append(arg.absolute)
        return " ".join(ret)

    def set_file_param(self, arg):
        self.fuzz_arg = arg
        self.fuzz_type = "file"

    def set_proto_param(self, port):
        self.host = '127.0.0.1'
        self.port = port
        self.fuzz_type = "proto"

    def is_elf(self):
        with open(self.exe, 'rb') as fd:
            flag = fd.read(4)
            if flag == b'\x7fELF':
                return True
            return False
    def can_fuzz(self):
        if not self.is_elf():
            return False
        self.analyse_argument()
        fddir = "/proc/{}/fd".format(self.pid)
        for item in os.listdir(fddir):
            link = os.path.join(fddir, item)
            real = os.readlink(link)
            # 1. check socket
            if 'socket' in real:
                inode = real[real.rfind('[')+1:-1]
                for tcp in tcp_list:
                    if tcp.inode == int(inode):
                        if tcp.status != 0xA:
                            return False
                        if int(tcp.lp) == 27017:
                            return False
                        if int(tcp.lp) == 22:
                            return False
                        self.proto = "TCP"
                        self.set_proto_param(tcp.lp)
                        #print('socket: ', real)
                        return True
                continue

            # 2. check file
            if not os.path.isfile(real):
                continue

            # check if file is not data and not text 
            """
            with open(real, 'rb') as fd:
                b = fd.read(1)
                print(real, b)
                if int.from_bytes(b,'little') < 127:
                    continue
            """
            ftype = os.popen("file {}".format(real)).read()
            if "data" in ftype:
                continue
            pure = simple(real)
            if pure.startswith('afl'):
                continue
            if pure not in self.argmap.keys():
                continue
            # only here can get the abs file path
            self.argmap[pure].set_abs(real)
            # skip ASII text
            if "ASCII text" in ftype:
                continue

            fuzz_arg = self.argmap[pure]
            fuzz_arg.set_fuzz_flag()
            self.set_file_param(fuzz_arg)
            return True

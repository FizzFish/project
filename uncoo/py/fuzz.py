#!/usr/bin/python2

import os, sys, shutil
import stat
import subprocess
from Queue import PriorityQueue
from common import Logger, simple
import time
import unshare

logger = Logger(__name__).getlogger()
pq_fuzzer = PriorityQueue()
cur_fuzzer = None

def check_env():
    """
    with open("/proc/sys/kernel/core_pattern", 'r') as fd:
        pattern = fd.read()
        if pattern != "core":
            print("need update pattern")
    with open("/proc/sys/kernel/core_pattern", 'w') as fd:
        fd.write("core")
    """
    pass
    # /sys/devices/system/cpu
    # os.system("echo performance | tee cpu*/cpufreq/scaling_governor")

ENV = ".env"

def detect_proto(pkts, proc):
    kb = ['RTSP', 'HTTP', 'FTP']
    for pkt in pkts:
        for proto in kb:
            if proto in pkt:
                proc.proto = proto
                return proto

def prepare_fuzz(proc, pkts=None):
    simexe = simple(proc.exe)
    logger.info("[+] prepare_fuzz proc {}".format(simexe))
    root = os.path.join(ENV, simexe)
    indir = os.path.join(root, "in")
    outdir = os.path.join(root, "out")
    if not os.path.isdir(ENV):
        os.mkdir( ENV, 0o755 )
    if not os.path.isdir(root):
        os.mkdir( root, 0o755 )

    fuzz_exe = os.path.join(root, simexe)
    shutil.copy(proc.exe, fuzz_exe)

    if not os.path.isdir(indir):
        os.mkdir(indir, 0o755)
    # clear outdir
    if os.path.isdir(outdir):
        #os.removedirs(outdir)
        os.system("rm -rf {}".format(outdir))
    os.mkdir(outdir, 0o755)
    # fuzz file
    if proc.fuzz_type == "file":
        source = proc.fuzz_arg.absolute
        destion = os.path.join(indir, proc.fuzz_arg.simple)
        shutil.copyfile(source, destion)
        logger.info("[*] copy file {} to {}".format(source, destion))

        fuzz_cmd = '/home/lius/tardigrade/bin/uncoo-fuzz -i {} -o {} -Q -m none ./{} '.format(indir, outdir, fuzz_exe)
        fuzz_cmd += proc.gen_fuzz_args()
    else:
        """
            ./uncoo-fuzz -Q -d -i in -o out \
            -N tcp://127.0.0.1/8554 \
            -x rtsp.dict \
            -P RTSP -D 10000 -q 3 -s 3 -E -K -R \
            ./testOnDemandRTSPServer 8554
        """
        detect_proto(pkts, proc)

        destion = os.path.join(indir, "init.raw")
        with open(destion, 'wb') as fd:
            for pkt in pkts:
                fd.write(pkt)
        logger.info("[*] write pcap as input file({})".format(destion))

        fuzz_cmd = '/home/lius/tardigrade/bin/net/uncoo-fuzz -i {} -o {} -Q -d '.format(indir, outdir)
        fuzz_cmd += "-N tcp://{}/{} ".format(proc.host, proc.port)
        #fuzz_cmd += "-x rtsp.dict "
        fuzz_cmd += "-P {} -D 10000 -q 3 -s 3 -E -K -R ./{} ".format(proc.proto, fuzz_exe)
        fuzz_cmd += proc.gen_fuzz_args()

    logger.info(fuzz_cmd)
    cmd = os.path.join(root, "cmd")
    with open(cmd, 'w') as fd:
        fd.write(fuzz_cmd)
    #os.chmod(cmd, stat.S_IRWXU)
    fuzzer = Fuzzer(root, proc.fuzz_type)
    pq_fuzzer.put(fuzzer)
        
class Fuzzer:
    crash_weight = 100
    hang_weight = 50
    favpath_weight = 10
    path_weight = 1
    def __init__(self, root, fuzz_type):
        self.root = root
        self.fuzz_type = fuzz_type
        self.time = 0
        self.score = sys.maxsize
    def analyse_fuzzer_stats(self, stat_file): 
        with open(stat_file, 'r') as fd:
            lines = fd.readlines()
        score = 0
        for line in lines:
            if 'unique_crashes' in line:
                crash_num = int(line[line.rfind(':')+1:])
                score += (Fuzzer.crash_weight*crash_num)
            elif 'unique_hangs' in line:
                hang_num = int(line[line.rfind(':')+1:])
                score += (Fuzzer.hang_weight*hang_num)
            elif 'paths_total' in line:
                path_num = int(line[line.rfind(':')+1:])
                score += (Fuzzer.path_weight*path_num)
            elif 'paths_favored' in line:
                favpath_num = int(line[line.rfind(':')+1:])
                score += (Fuzzer.favpath_weight*favpath_num)
        return score

    def update_score(self):
        stat_file = os.path.join(self.root, "out/fuzzer_stats")
        score = 0
        if os.path.exists(stat_file):
            score = self.analyse_fuzzer_stats(stat_file)
        else:
            crash_path = os.path.join(self.root, "out/crashes")
            hang_path = os.path.join(self.root, "out/hangs")
            if os.path.isdir(crash_path):
                crash_num = len(os.listdir(crash_path))
                score += (Fuzzer.crash_weight*crash_num)
            if os.path.isdir(hang_path):
                hang_num = len(os.listdir(hang_path))
                score += (Fuzzer.hang_weight*hang_num)

        if self.time > 0:
            self.score = score / self.time
        print("{} score: {}".format(self.root, self.score))

    # __lt__ is adverse for priority queue getting the biggest score
    def __lt__(self, other):
        return self.score > other.score

    def fuzz(self):
        cmdfile = os.path.join(self.root, 'cmd')
        with open(cmdfile, 'r') as fd:
            cmd = fd.read()
        self.fuzz_start_time = time.time()
        print("[+] exec cmd: {}".format(cmd))
        cmdline = cmd.split()
        if self.fuzz_type == 'proto':
            print("new net unshare")
            unshare.unshare(unshare.CLONE_NEWNET)
            subprocess.call(['ip', 'link', 'set', 'up', 'lo'])
            #print(os.popen('ifconfig').read())
        self.fuzz_sub = subprocess.Popen(cmdline)#, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


    def stop(self):
        print("[-] stop fuzz {}".format(self.root))
        self.fuzz_sub.terminate()
        self.time += (time.time() - self.fuzz_start_time)
        self.update_score()

def schedule_fuzzer():
    global cur_fuzzer
    if cur_fuzzer:
        cur_fuzzer.stop()
        pq_fuzzer.put(cur_fuzzer)
    if not pq_fuzzer.empty():
        cur_fuzzer = pq_fuzzer.get()
        logger.info("schedule fuzzer {}".format(cur_fuzzer.root))
        cur_fuzzer.fuzz()
        


    

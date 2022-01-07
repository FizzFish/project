#!/usr/bin/python2
import os, sys, stat
import time
from process import Process, get_tcp_list
from fuzz import prepare_fuzz, schedule_fuzzer, check_env
from threading import Thread, Event
from scapy.all import sniff
from common import Logger, simple
import pdb
import schedule

scanned_pidset = set()
logger = Logger(__name__).getlogger()


class Sniffer(Thread):
    def __init__(self, proc):
        #super(Thread, self).__init__()
        Thread.__init__(self)
        self.iface = 'lo'
        self.proc = proc
        self.pkts = []
        self.last_time = 0
        self.count = 0
        #self.stop_event = Event()

    def run(self):
        rule = "dst port {}".format(self.proc.port)
        sniff(iface=self.iface, prn=self.sniff_cb, filter=rule, stop_filter=self.check_stop_sniff)

        prepare_fuzz(self.proc, self.pkts)

    def stop(self):
        self.stop_event.set()

    def check_stop_sniff(self, pkt):
        """
        val = time.time() - self.last_time
        print("eclpsed {} seconds".format(val))
        #if time.time() - self.last_time > 5:
        if val > 5:
            print("sniff stop")
            return True
        """
        flags = pkt['TCP'].flags
        return (flags & 1) == 1

    def sniff_cb(self, pkt):
        #self.last_time = time.time()
        if pkt.haslayer('Raw'):
            self.count += 1
            # wrongly recv twice package when sniff lo
            if self.iface == 'lo' and self.count % 2 == 0:
                return
            raw = pkt.load
            #print(raw)
            self.pkts.append(raw)



"""
for i in range(3):
    print("scan {} times".format(i))
    scan_process()
    time.sleep(5)
proc = Process(98240)
proc.can_fuzz()
sniffer = Sniffer(proc)
sniffer.start()
time.sleep(5)
"""

"""
scann new process, update scanned_pidset
generate Process(pid) and show fuzz params
add file_fuzz process to ready_proc, proto_fuzz
process to wait_proc.
if find new proc needing sniff, then sniff them.
"""
def scan_process():
    get_tcp_list()
    logger.info("scan process...")
    cmd = "ps kstart_time -ef | awk '($3>2){print $2}'"
    result= os.popen(cmd).read()
    pids = result.split('\n')
    pidset = set(pids[1:-1][::-1])
    global scanned_pidset
    newpidset = pidset - scanned_pidset
    #print("newpidset: ", newpidset)
    scanned_pidset |= newpidset

    for pid in newpidset:
        try:
            proc = Process(pid)
            if proc.can_fuzz():
                os.system("mkdir .cobot")
                os.system("cp {} .cobot/{}".format(proc.exe, simple(proc.exe)))
                os.system("java -jar binary.jar -p='.cobot'")
                if proc.fuzz_type == "file":
                    prepare_fuzz(proc)
                else:
                    logger.info("[+] start sniffer for [{}:{}]".format(proc.pid, proc.port))
                    sniffer = Sniffer(proc)
                    sniffer.start()
        except (IOError, OSError):
            pass
        #except PermissionError:
        #    pass
        except Exception as exc:
            # may proc not exist
            #print(type(exc), exc)
            continue

#os.system("rm -f log")
check_env()

scan_process()
schedule_fuzzer()
schedule.every(10).seconds.do(scan_process)
schedule.every(40).seconds.do(schedule_fuzzer)

while True:
    schedule.run_pending()

"""
scan_process()
time.sleep(3)
print("scan_process end")
schedule_fuzzer()
schedule_fuzzer()
"""

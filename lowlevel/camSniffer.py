#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct
import sys
import pcap
import dpkt
import urllib
import FoscDecoder

""" analyse a packet capture either live or from a file

    The main goal for this program is to analyse the traffic between the Foscam Windows
    browser plugin and a Foscam FI9821W V2.  This is one of their cheaper HD H.264 cameras.

    On Linux this browser plugin does not work, and the remaining web interface only allows
    to change some basic camera settings.

    Most of the plugins functionality can be duplicated by a couple of CGI calls, which are
    documented in their SDK.  However, some functions are only available by a low level
    protocol, e.g. the "talk function" (sending audio to the camera).

    For their older models Foscam has published this low level protocol.
    As of the time of writing (end 2013) the documents for this model are not (yet?) available.

    The "interesting" packets are TCP/IP packets. Their structure starts with:

    int32 commmand     (little endian)
    char4 magic number "FOSC"
    int32 datalen      length of the data section (I'm already guessing here)

    The program allows to analyse either a live capture (and optionally dump the received packets)
    or the packet dump itself (see "main" below).

    Dependencies:
    - python-libpcap  for the package capture
    - python-dpkt     for easier access to the IP structure

    Note: dpkt doesn't do any stream reassembling, i.e. if can't handle data larger than one packet,
          e.g. audio or video strams.

    Possible live capture scenario:
    - Linux box used as router for a Windows computer
    - Linux host sniffing the packets
    or
    - Linux box with Virtualbox running Windows
    - Firefox with plugin running under Windows
    - Linux host sniffing the packets

    This program has not been tested under Windows, but I don't see large difficulties if the
    dependencies are satisfied.

    Known issue:
    This program only analyzes sniffed tcp packets.  If a command does not start at the begin of a packet (which
    is rare, but does happen), or data is split into multiple tcp packets (e.g. video or audio data), the decoders
    will not work correctly.  No attempt has been made to reassemble the packets.
"""



def print_src_dest_ip(ip):
    """ output source and destination IP address (and ports, if possible)
    """
    srcip = socket.inet_ntoa(ip.src)
    dstip = socket.inet_ntoa(ip.dst)

    # only TCP packets have ports
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        srcip += ":%s" % ip.tcp.sport
        dstip += ":%s" % ip.tcp.dport
    print "%s -> %s" % (srcip, dstip)


class analyser(object):
    """ analyser base object

    does some house keeping for the sub classes
    """
    def __init__(self):
        self.firsttimestamp = None
        self.rel_timestamp = None
        self.count = 0
        self.count_shown = 0

        self.compdata = None
        self.compdata_allequal = True

    def process_packet(self, pktlen, data, timestamp):
        """ count packets and calculate relative timestamp

        .. note:: sub classes should call this one first
        """
        self.count += 1

        if self.firsttimestamp is None:
            self.firsttimestamp = timestamp
        self.rel_timestamp = timestamp - self.firsttimestamp

    def count_as_shown(self):
        """ increase another counter for the final stats
        """
        self.count_shown += 1

    def test_data(self,data):
        """ determine if the content of all packets handed to this function are equal
        .. note:: shows up in the final stats
        .. note:: useful to check if the content of a given command packet changes or not
        """
        # check if the content of all packets is equal
        if self.compdata is None:
            self.compdata = data
        else:
            if self.compdata_allequal and (self.compdata != data):
                self.compdata_allequal = False

    def print_stat(self):
        """ give some stats
        """
        print "Number of packets:", self.count
        print "........... shown:", self.count_shown
        if self.compdata_allequal and not self.compdata is None:
            print "all tested data packets were equal"

class packet_source(object):
    """ packet source base object
    """
    def __init__(self,analyser):
        self.analyser = analyser()

    def loop(self):
        """ loop through all packets

        override me!
        """
        pass

    def print_analyser_stat(self):
        self.analyser.print_stat()

class live_source(packet_source):
    """ a live capture packet source
    """
    def __init__(self, analyser, device, filter=None, filename = None):
        """ constructor
        :param analyser: the uninstantiated analyser class
        :param device: the device to listen to (e.g. "eth0", "wlan1")
        :param filter: optional filter (pcap notation, e.g. "ip host 192.168.0.102", "UDP")
        """

        self.p = pcap.pcapObject()
        self.p.open_live(device, 65535, 0, 100)  # device, snaplength, promiscous_mode, timeout

        if not filter is None:
            self.p.setfilter(filter, 0, 0)

        self.dumper = False
        if not filename is None:
            self.p.dump_open(filename)
            self.dumper = True
        packet_source.__init__(self,analyser)


    def loop(self):
        """ loop intended to for console, press ^C to stop
        """
        try:
            while 1:
                self.p.dispatch(1, self.analyser.process_packet)
                if self.dumper:
                    self.p.dispatch(1,None)
        except KeyboardInterrupt:
            print '%s' % sys.exc_type
            print 'shutting down'
            print '%d packets received, %d packets dropped, %d packets dropped by interface' % self.p.stats()

class file_source(packet_source):
    """ a packet source reading from a dump file
    """
    def __init__(self, analyser, filename):
        """ constructor
        :param analyser: the uninstantiated analyser class
        :param filename: filename of the capture file
        """
        packet_source.__init__(self,analyser)

        self.p = pcap.pcapObject()
        self.p.open_offline(filename)

    def loop(self):
        # "-1" = loop through all entries
        self.p.dispatch(-1, self.analyser.process_packet)


class fosc_analyser(analyser):
    """ class to analyse the live or offline capture
    """

    def __init__(self):
        analyser.__init__(self)

        # Some additional general stats:
        #
        # remember:  remember the order in which the commands are found
        # stat:      count how many of each command were detected
        self.remember = []
        self.stat = {}

        self.errors = []

        self.descriptions = FoscDecoder.decoder_descriptions
        self.call = FoscDecoder.decoder_call

    def remember_me(self,cmd):
        self.remember.append(cmd)
        if cmd in self.stat:
            self.stat[cmd] += 1
        else:
            self.stat[cmd] = 1

    def print_stat(self):
        analyser.print_stat(self)
        print "Remember"
        print self.remember
        for x in sorted(self.stat):
            print "cmd %s: %s" % (x, self.stat[x])
        if len(self.errors) > 0:
            print "Decoding errors in cmds:", self.errors

    def process_packet(self, pktlen, data, timestamp):
        global verbose
        global camera_ip

        def possiblemeaning(no):
            return self.descriptions.get(no,"???")

        def possibledecode(no, data):
            func = self.call.get(cmd, FoscDecoder.printhex)
            error = func(ip.tcp.data)
            if not error is None:
                if not no in self.errors:
                    self.errors.append(no)
                print error

        # call super methode for some housekeeping
        analyser.process_packet(self,pktlen, data, timestamp)

        # let dpkt analyse the packet
        ether = dpkt.ethernet.Ethernet(data)

        # is it an IP packet?
        if ether.type != dpkt.ethernet.ETH_TYPE_IP:
           return

        # get the content of the IP packet
        ip = ether.data

        # is it a TCP/IP packet?
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            return

        # only traffic, from/to the camera
        if not ( socket.inet_ntoa(ip.src) == camera_ip or socket.inet_ntoa(ip.dst) == camera_ip):
            return

        # check for HTTP traffic
        try:
            http_rq = dpkt.http.Request(ip.tcp.data)
            print "\nURL-Req:", urllib.unquote(http_rq.uri)
            self.remember_me(http_rq.uri)
        except dpkt.dpkt.UnpackError:
            pass

        # check for "low/level" traffic
        # is the tcp data larger than 12 bytes?
        # 4 bytes length information, 4 bytes "FOSC", 4 bytes data len
        if len(ip.tcp.data)<12:
            return

        # unpack those 8 bytes
        cmd, magic, datalen = FoscDecoder.unpack("<I4sI",ip.tcp.data)

        # is the "magic" identifier present?
        if magic != 'FOSC':
            return

        # ignore LoninTest/Reply
        if cmd in [15,29]: return

        # ignore video in
        if cmd == 26: return

        # if cmd != 0: return
        # diff = FoscDecoder.datacomp.put(ip.tcp.data)
        # FoscDecoder.printhex(ip.tcp.data, "cmd0", diff)
        # return

        # if not cmd in [111]: return
        # if cmd in [12, 15, 29, 26]: return

        if not verbose:
            print cmd
            return

        # stop after a given number of decoded packets
        # if self.count_shown > 10: return
        # if datalen <= 996: return    # 1956

        # do some stats
        self.count_as_shown()
        analyser.test_data(self,ip.tcp.data)
        self.remember_me(cmd)

        print
        print_src_dest_ip(ip)
        if socket.inet_ntoa(ip.src) == camera_ip:
            print "Camera -> User"
        if socket.inet_ntoa(ip.dst) == camera_ip:
            print "User -> Camera"

        print "#%s @ %s:" % (self.count, self.rel_timestamp)  # position in pcap file
        print "command %s: %s" % (cmd, possiblemeaning(cmd))
        print "tcp data length:", len(ip.tcp.data)
        print "datalen", datalen
        if (datalen+12) != len(ip.tcp.data):
            print "Packet length mismatch! Multiple commands in one packet/one command in multiple packets?"
        possibledecode(cmd,ip.tcp.data)
        if (datalen+12) < len(ip.tcp.data):
            print "Additional data:"
            FoscDecoder.printhex(ip.tcp.data[datalen+12:])

if __name__=='__main__':
    """ in live mode, you need root privileges

     In order to start the live sniffer, go to the command line and enter:
     sudo python camSniffer.py live

     If not started in live mode, it analyses the file defined in recfile.
    """

    try:
        if sys.argv[1] == "live":
            live = True
    except IndexError:
        live = False

    if live: print "Live mode"

    verbose = True
    camera_ip = "192.168.0.102"
    recfile = "test4.pcap"
    playfile = recfile

    if live:
        verbose = False

    verbose = True
    audiodump = None # open("/tmp/audio.bin","wb")

    if live:
        # note: live_source usually needs root permissions
        ana = live_source(fosc_analyser,
                          device = "eth0",         # "wlan1", ...
                          filter = None,           # "ip host 192.168.0.102", or None
                          filename = recfile       # dump to file, or None
                        )
    else:
        ana = file_source(fosc_analyser,recfile)

    ana.loop()
    print
    ana.print_analyser_stat()

    FoscDecoder.datacomp.stats()

    if not audiodump is None:
        audiodump.close()

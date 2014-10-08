#! /usr/bin/env python

from scapy.all import *

'''
Reference from RFC793(Page 23] http://tools.ietf.org/html/rfc793#section-3.3

                              +---------+ ---------\      active OPEN
                              |  CLOSED |            \    -----------
                              +---------+<---------\   \   create TCB
                                |     ^              \   \  snd SYN
                   passive OPEN |     |   CLOSE        \   \
                   ------------ |     | ----------       \   \
                    create TCB  |     | delete TCB         \   \
                                V     |                      \   \
                              +---------+            CLOSE    |    \
                              |  LISTEN |          ---------- |     |
                              +---------+          delete TCB |     |
                   rcv SYN      |     |     SEND              |     |
                  -----------   |     |    -------            |     V
 +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 |         |<-----------------           ------------------>|         |
 |   SYN   |                    rcv SYN                     |   SYN   |
 |   RCVD  |<-----------------------------------------------|   SENT  |
 |         |                    snd ACK                     |         |
 |         |------------------           -------------------|         |
 +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
   |           --------------   |     |   -----------
   |                  x         |     |     snd ACK
   |                            V     V
   |  CLOSE                   +---------+
   | -------                  |  ESTAB  |
   | snd FIN                  +---------+
   |                   CLOSE    |     |    rcv FIN
   V                  -------   |     |    -------
 +---------+          snd FIN  /       \   snd ACK          +---------+
 |  FIN    |<-----------------           ------------------>|  CLOSE  |
 | WAIT-1  |------------------                              |   WAIT  |
 +---------+          rcv FIN  \                            +---------+
   | rcv ACK of FIN   -------   |                            CLOSE  |
   | --------------   snd ACK   |                           ------- |
   V        x                   V                           snd FIN V
 +---------+                  +---------+                   +---------+
 |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 +---------+                  +---------+                   +---------+
   |                rcv ACK of FIN |                 rcv ACK of FIN |
   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
   |  -------              x       V    ------------        x       V
    \ snd ACK                 +---------+delete TCB         +---------+
     ------------------------>|TIME WAIT|------------------>| CLOSED  |
                              +---------+                   +---------+
 
                      TCP Connection State Diagram

'''

class TCPConnectionState(Automaton):
	do_debug = None 

	cond_pkt = None
	action_pkt = None

	def parse_args(self, peer_ip = "192.168.2.1", peer_port = 5001, local_ip = "192.168.15.23", local_port = 12345, **kargs):
		Automaton.parse_args(self, **kargs)
		self.peer_ip = peer_ip
		self.peer_port = peer_port
		self.local_ip = local_ip
		self.local_port = local_port

	def master_filter(self, pkt):
		return (IP in pkt and pkt[IP].src == self.peer_ip
			and TCP in pkt and pkt[TCP].sport == self.peer_port)

	@ATMT.state(initial=1)
	def START(self):
		print "State=START"

	@ATMT.condition(START)
	def active_open(self):
		print "active open..."
		raise self.SYN_SENT()

	@ATMT.action(active_open)
	def send_syn(self):
		print "try to send SYN"
		self.action_pkt=IP(src=self.local_ip, dst=self.peer_ip)/TCP(dport=self.peer_port, sport=self.local_port, flags="S")
		send(self.action_pkt)

	@ATMT.state()
	def SYN_SENT(self):
		print "State=SYN_SENT"

	@ATMT.receive_condition(SYN_SENT)
	def recv_syn_ack(self, pkt):
		if pkt[TCP].flags == 0x12:
			print "recv SYN,ACK"
			self.cond_pkt = pkt
			raise self.ESTABLISHED()
		else:
			if self.do_debug:
				pkt.show()



	@ATMT.action(recv_syn_ack)
	def send_ack(self):
		self.action_pkt.seq=self.cond_pkt[TCP].ack
		self.action_pkt.ack=ack=self.cond_pkt[TCP].seq+1
		self.action_pkt[TCP].flags="A"
		self.action_pkt[TCP].sport=self.cond_pkt[TCP].dport
		if self.do_debug:
			self.action_pkt.show()
		send(self.action_pkt)

	@ATMT.state()
	def ESTABLISHED(self):
		print "State=ESTABLISHED"

	@ATMT.condition(ESTABLISHED)
	def do_close(self):
		raise self.FIN_WAIT_1()

	@ATMT.action(do_close)
	def send_fin(self):
		self.action_pkt.seq=self.cond_pkt[TCP].ack
		self.action_pkt.ack=ack=self.cond_pkt[TCP].seq+1
		self.action_pkt[TCP].flags="FA"
		self.action_pkt[TCP].sport=self.cond_pkt[TCP].dport
		if self.do_debug:
			self.action_pkt.show()
		send(self.action_pkt)

	@ATMT.state()
	def FIN_WAIT_1(self):
		print "state=FIND_WAIT_1"

	@ATMT.receive_condition(FIN_WAIT_1)
	def recv_fin(self, pkt):
		self.cond_pkt = pkt
		if pkt[TCP].flags == 0x10:
			print "recv ACK"
			raise self.FIN_WAIT_2()
		elif pkt[TCP].flags == 0x1:
			print "recv FIN"
			raise self.CLOSING()
		elif pkt[TCP].flags == 0x11:
			print "recv FIN,ACK"
			raise self.TIME_WAIT()
		else:
			if self.do_debug:
				pkt.show()

	@ATMT.action(recv_fin)
	def fin_wait_1_send(self):
		if self.cond_pkt[TCP].flags == 0x10:
			print "send <nothing>"
		else:
			self.send_ack()
			print "send ACK"

	@ATMT.state()
	def FIN_WAIT_2(self):
		print "state=FIN_WAIT_2"

	@ATMT.receive_condition(FIN_WAIT_2)
	def fwait2_recv_fin(self, pkt):
		if TCP in pkt and pkt[TCP].flags & 0x1:
			print "recv FIN"
			raise self.TIME_WAIT()

	@ATMT.action(fwait2_recv_fin)
	def fwait2_send_ack(self):
		print "send ACK"
		self.send_ack()

	@ATMT.state()
	def CLOSING(self):
		print "state=CLOSING"

	@ATMT.receive_condition(CLOSING)
	def closing_recv_ack(self, pkt):
		self.cond_pkt = pkt
		if pkt[TCP].flags == 0x10:
			print "recv ACK"
			raise self.TIME_WAIT()

	@ATMT.action(closing_recv_ack)
	def closing_send(self):
		print "send <nothing>"

	@ATMT.state()
	def TIME_WAIT(self):
		print "state=TIME_WAIT"

	@ATMT.timeout(TIME_WAIT, 3)
	def twait_timeout(self):
		raise self.CLOSED()

	@ATMT.action(twait_timeout)
	def goto_closed(self):
		print "...."

	@ATMT.state(final=1)
	def CLOSED(self):
		print "State=CLOSED"

def main(argv=None):
	conf.route.add(net="192.168.2.1/32", gw="192.168.15.1")
	try: TCPConnectionState().run()
	finally: print "end...."


if __name__ == '__main__': sys.exit(main())


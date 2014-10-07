TCPConnectionState
==================

TCP Connection State implement with Scapy

First Round mode(active OPEN):

 Server: iperf -s -i 1 &
         tcpdump -n -i ethX -S

	03:31:13.203499 IP 192.168.2.100.63521 > 192.168.2.1.5001: Flags [S], seq 0, win 8192, length 0
	03:31:13.203562 ARP, Request who-has 192.168.2.100 tell 192.168.2.1, length 28
	03:31:13.203812 ARP, Reply 192.168.2.100 is-at 02:09:21:7d:a2:04, length 46
	03:31:13.203843 IP 192.168.2.1.5001 > 192.168.2.100.63521: Flags [S.], seq 540514762, ack 1, win 14600, options [mss 1460], length 0
	03:31:13.268042 IP 192.168.2.100.63521 > 192.168.2.1.5001: Flags [.], ack 540514763, win 8192, length 0
	03:31:13.278226 IP 192.168.2.100.63521 > 192.168.2.1.5001: Flags [F.], seq 1, ack 540514763, win 8192, length 0
	[  5] local 192.168.2.1 port 5001 connected with 192.168.2.100 port 63521
	03:31:13.278413 IP 192.168.2.1.5001 > 192.168.2.100.63521: Flags [.], ack 2, win 14600, length 0
	[  5]  0.0- 0.0 sec  0.00 Bytes  0.00 bits/sec
	03:31:13.288598 IP 192.168.2.1.5001 > 192.168.2.100.63521: Flags [F.], seq 540514763, ack 2, win 14600, length 0
	03:31:13.320432 IP 192.168.2.100.63521 > 192.168.2.1.5001: Flags [.], ack 540514764, win 8192, length 0
	03:31:18.272415 ARP, Request who-has 192.168.2.1 tell 192.168.2.100, length 46
	03:31:18.272415 ARP, Reply 192.168.2.1 is-at 36:b6:70:90:76:10, length 28

 Client: sudo ./TCPConnectionState.py
	....
	yellow@linuxlite-yellow:~/work% sudo ./MyTCPState.py
	WARNING: No route found for IPv6 destination :: (no default route?)
	State=START
	active open...
	try to send SYN
	.
	Sent 1 packets.
	State=SYN_SENT
	recv SYN,ACK
	.
	Sent 1 packets.
	State=ESTABLISHED
	.
	Sent 1 packets.
	state=FIND_WAIT_1
	recv ACK
	send <nothing>
	state=FIN_WAIT_2
	recv FIN
	send ACK
	.
	Sent 1 packets.
	state=TIME_WAIT
	....
	State=CLOSED
	end....


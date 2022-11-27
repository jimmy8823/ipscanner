CC:=gcc

ipscanner: pcap.o main.o fill_packet.o
	$(CC) -o ipscanner pcap.o main.o fill_packet.o -lpcap
main.o:
	$(CC) -c pcap.c main.c fill_packet.c
pcap.o:
	$(CC) -c pcap.c
fill_packet.o:
	$(CC) -c fill_packet.c 

clean:
	rm -f pcap.o main.o fill_packet.o
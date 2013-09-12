compile:
	@gcc src/sniffer.c -o sniffer -lpcap -Wall

clean:
	@rm sniffer

test:
	@./sniffer -i eth0 -f "port 23"

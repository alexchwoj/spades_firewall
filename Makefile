all:
	gcc spadesfwall.c -o spadesfwall -pthread -lpcap

clean:
	$(RM) spadesfwall
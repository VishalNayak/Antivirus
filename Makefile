all:
	${MAKE} -C kmodule
	${MAKE} -C src 
	${MAKE} -C tools 

clean:
	${MAKE} -C kmodule clean
	${MAKE} -C src clean
	${MAKE} -C tools clean

install:  antivirus  blacklist  whitelist
	mkdir -p /etc/netcop
	cp ./antivirus /bin/
	cp ./blacklist /etc/netcop/
	chmod 644 /etc/netcop/blacklist
	cp ./whitelist /etc/netcop/
	chmod 644 /etc/netcop/whitelist
	touch /tmp/antivirus.log
	chmod 666 /tmp/antivirus.log
	insmod kmodule/netcop.ko
	

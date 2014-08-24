PLUGIN := check_nwc_health
CLEANFILES := check_nwc_health

include ../common.mk

check_nwc_health:
	set -e; for i in guess sub; do if [ ! -e src/config.$$i.bak ]; then cp src/config.$$i src/config.$$i.bak; fi; done
	cp /usr/share/misc/config.* src
	cd src && ./configure --prefix=/usr --with-nagios-user=nagios --with-nagios-group=nagios
	make -C src
	sed 's,^# nagios: +epn$,# nagios: -epn\n,' src/plugins-scripts/check_nwc_health > $@
	#cp src/plugins-scripts/check_nwc_health $@

clean::
	[ ! -f src/Makefile ] || make -C src distclean
	set -e; for i in guess sub; do if [ -e src/config.$$i.bak ]; then mv src/config.$$i.bak src/config.$$i; fi; done

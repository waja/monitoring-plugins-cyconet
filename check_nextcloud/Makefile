PLUGIN := check_nextcloud
CLEANFILES := check_nextcloud
DOCFILES := README.md

include ../common.mk

check_nextcloud:
	cp check/$@.py $@
	chmod 755 $@

install::
	install -d $(DESTDIR)$(PLUGINDIR)
	ln -s $(PLUGINDIR)/$(PLUGIN) $(DESTDIR)$(PLUGINDIR)/$(PLUGIN).py


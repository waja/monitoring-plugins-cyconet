PLUGIN := check_pve
CLEANFILES := check_pve
DOCFILES := src/README.md src/CODE_OF_CONDUCT.md src/CONTRIBUTING.md

include ../common.mk

check_pve:
	cp src/$@.py $@
	chmod 755 $@

install::
	install -d $(DESTDIR)$(PLUGINDIR)
	ln -s $(PLUGINDIR)/$(PLUGIN) $(DESTDIR)$(PLUGINDIR)/$(PLUGIN).py


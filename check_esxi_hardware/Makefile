PLUGIN := check_esxi_hardware
CLEANFILES := check_esxi_hardware
DOCFILES := README.md

include ../common.mk

check_esxi_hardware:
	cp $@.py $@
	chmod 755 $@

install::
	install -d $(DESTDIR)$(PLUGINDIR)
	ln -s $(PLUGINDIR)/$(PLUGIN) $(DESTDIR)$(PLUGINDIR)/$(PLUGIN).py


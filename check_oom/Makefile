PLUGIN := check_oom
CLEANFILES := check_oom
DOCFILES := README.md

include ../common.mk

check_oom:
	cp $@.py $@
	chmod 755 $@

install::
	install -d $(DESTDIR)$(PLUGINDIR)
	ln -s $(PLUGINDIR)/$(PLUGIN) $(DESTDIR)$(PLUGINDIR)/$(PLUGIN).py


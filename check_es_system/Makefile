#/usr/bin/make -f

PLUGIN = src/check_es_system
CLEANEXTRAFILES = $(PLUGIN)
DOCFILES = src/README.md

include ../common.mk

src/$(PLUGIN): src/$(PLUGIN).sh
	cp $< $@

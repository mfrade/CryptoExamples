TOPTARGETS := all clean

# SUBDIRS := $(wildcard */.)
SUBDIRS := file-encryption-with-password

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

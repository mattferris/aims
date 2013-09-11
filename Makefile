#
# Makefile for aims2
#
# Builds binary packages for distribution
#

BRANCH=master
RELEASE=latest
TMPDIR = tmp
CLEAN=true

deb:
	if [ -d $(TMPDIR) ]; then rm -r $(TMPDIR); fi
	mkdir -p $(TMPDIR)/_work
	git archive --format=tar $(BRANCH) | ( cd $(TMPDIR)/_work && tar xf - )
	chown -R root:root $(TMPDIR)/*
	chmod -R u=rwX,g=rX,o=rX $(TMPDIR)/*
	mkdir -p $(TMPDIR)/usr/sbin $(TMPDIR)/usr/share/aims $(TMPDIR)/etc/aims $(TMPDIR)/usr/lib/perl5; \
	mv $(TMPDIR)/_work/bin/* $(TMPDIR)/usr/sbin/; \
	mv $(TMPDIR)/_work/lib/* $(TMPDIR)/usr/lib/perl5/; \
	mv $(TMPDIR)/_work/docs $(TMPDIR)/usr/share/aims/
	mv $(TMPDIR)/_work/man $(TMPDIR)/usr/share/
	find $(TMPDIR)/usr/share -name "*.md" -delete
	rm -r $(TMPDIR)/_work
	cp -r build/meta/deb/* $(TMPDIR)/
	mv $(TMPDIR)/aims.rules $(TMPDIR)/etc/aims/; \
	cat $(TMPDIR)/DEBIAN/control | sed s/\<ver\>/$(RELEASE)/ > $(TMPDIR)/DEBIAN/control.new
	mv $(TMPDIR)/DEBIAN/control.new $(TMPDIR)/DEBIAN/control
	( cd $(TMPDIR) && find . ! -path "./DEBIAN/*" ! -name DEBIAN -type f -print0 | xargs -0 md5sum >> DEBIAN/md5sums )
	dpkg-deb -b $(TMPDIR) aims2_$(RELEASE)_all.deb
	if [ "$(CLEAN)" = "true" ]; then rm -rf $(TMPDIR); fi

all: deb

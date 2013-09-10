#
# Makefile for aims2
#
# Builds binary packages for distribution
#

RELEASE=HEAD
TMPDIR = /tmp/aims2-build

deb:
	if [ -d $(TMPDIR) ]; then rm -r $(TMPDIR); fi
	mkdir -p $(TMPDIR)/_work
	git archive $(RELEASE) -o $(TMPDIR)/_work/tmp.tar
	( cd $(TMPDIR)/_work; tar xf tmp.tar )
	mkdir -p $(TMPDIR)/usr/sbin $(TMPDIR)/usr/share/aims $(TMPDIR)/etc/aims $(TMPDIR)/usr/lib/perl5; \
	mv $(TMPDIR)/_work/bin/* $(TMPDIR)/usr/sbin/; \
#	mv $(TMPDIR)/_work/etc/* $(TMPDIR)/etc/aims/; \
	mv $(TMPDIR)/_work/lib/* $(TMPDIR)/usr/lib/perl5/; \
	mv $(TMPDIR)/_work/docs $(TMPDIR)/usr/share/aims/
	rm -r $(TMPDIR)/_work
	find $(TMPDIR) -type f -print0 | xargs -0 md5sum >> $(TMPDIR).md5sums
	cp -r build/meta/deb/* $(TMPDIR)/
	mv $(TMPDIR).md5sums $(TMPDIR)/DEBIAN/md5sums
	dpkg-deb -b $(TMPDIR) aims2_$(RELEASE)_all.deb
	rm -r $(TMPDIR)

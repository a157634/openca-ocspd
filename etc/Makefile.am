## Process this file with automake to produce Makefile.in

TOP = ..

CHMOD = @CHMOD@

etc_prefix		= $(DESTDIR)${exec_prefix}/etc
lib_prefix		= $(DESTDIR)@libdir@
var_prefix		= $(DESTDIR)${exec_prefix}/var
doc_prefix		= $(DESTDIR)${datadir}/openca-prqpd

EXTRA_DIST = ocspd.xml.in ocspd.in ca.d/*.xml

install-data-local:
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(etc_prefix); \
	$(mkinstalldirs) $(etc_prefix)/init.d; \
	$(mkinstalldirs) -m 755 $(etc_prefix)/ocspd; \
	$(mkinstalldirs) -m 755 $(etc_prefix)/ocspd/certs; \
	$(mkinstalldirs) -m 755 $(etc_prefix)/ocspd/crls; \
	$(mkinstalldirs) -m 700 $(etc_prefix)/ocspd/private; \
	$(mkinstalldirs) -m 700 $(etc_prefix)/ocspd/ca.d; \
	$(mkinstalldirs) -m 755 $(etc_prefix)/ocspd/pki; \
	$(mkinstalldirs) -m 700 $(etc_prefix)/ocspd/pki/token.d; \
	$(mkinstalldirs) -m 700 $(etc_prefix)/ocspd/pki/hsm.d; \
	$(mkinstalldirs) -m 755 $(etc_prefix)/ocspd/pki/profile.d
	@for file in *.xml ; do \
	    if test -f $$file; then \
	      $(INSTALL_DATA) $$file $(etc_prefix)/ocspd; \
	    fi \
	  done ;
	@ $(INSTALL_DATA) ocspd $(etc_prefix)/init.d/; \
	$(CHMOD) +x $(etc_prefix)/init.d/ocspd ;
	@for file in token.d/*.xml ; do \
	    if test -f $$file ; then \
		$(INSTALL_DATA) $$file $(etc_prefix)/ocspd/pki/token.d ; \
	    fi ; \
	done ;
	@for file in hsm.d/*.xml ; do \
	    if test -f $$file ; then \
		$(INSTALL_DATA) $$file $(etc_prefix)/ocspd/pki/hsm.d ; \
	    fi ; \
	done ;
	@for file in ca.d/*.xml ; do \
	    if test -f $$file ; then \
		$(INSTALL_DATA) $$file $(etc_prefix)/ocspd/ca.d ; \
	    fi ; \
	done


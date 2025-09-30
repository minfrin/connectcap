
confdir = $(sysconfdir)/connectcap
dist_conf_DATA = ccpasswd

sysconfigdir = $(sysconfdir)/sysconfig
dist_sysconfig_DATA = connectcap

servicedir = $(prefix)/lib/systemd/system
dist_service_DATA = connectcap.service


install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/spool/connectcap

uninstall-local:
	rmdir $(DESTDIR)$(localstatedir)/spool/connectcap 2>/dev/null || :


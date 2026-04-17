
current_dir = $(shell pwd)

dev_install:
	@ echo "WARNING: THIS WILL BREAK EXISTING UNIXD INSTALLS"
	@ echo "ctrl-c now if this is not what you want"
	@ read
	@ echo "LAST CHANCE"
	@ sleep 5
	ln -s -f $(current_dir)/../platform/opensuse/netidm-unixd.service /etc/systemd/system/netidm-unixd.service
	ln -s -f $(current_dir)/../platform/opensuse/netidm-unixd-tasks.service /etc/systemd/system/netidm-unixd-tasks.service
	ln -s -f $(current_dir)/../target/debug/netidm-unix /usr/sbin/netidm-unix
	ln -s -f $(current_dir)/../target/debug/netidm_ssh_authorizedkeys /usr/sbin/netidm_ssh_authorizedkeys
	ln -s -f $(current_dir)/../target/debug/netidm_unixd_tasks /usr/sbin/netidm_unixd_tasks
	ln -s -f $(current_dir)/../target/debug/netidm_unixd /usr/sbin/netidm_unixd
	ln -s -f $(current_dir)/../target/debug/libpam_netidm.so /lib64/security/pam_netidm.so
	ln -s -f $(current_dir)/../target/debug/libnss_netidm.so /usr/lib64/libnss_netidm.so.2



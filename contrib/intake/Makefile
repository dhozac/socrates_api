build_name_fmt := $(shell rpm --eval '%{_build_name_fmt}' | sed 's/%%/%/')
INTAKE_RPM := $(shell rpm -q --specfile --qf $(build_name_fmt) intake.spec)

all: tftpboot/initrd0.img

$(INTAKE_RPM): intake.spec Makefile *.py *.service *.sh
	rpmbuild -bb --define '_sourcedir '`pwd` --define '_rpmdir '`pwd` $<
	createrepo .

intake.iso: kickstart.cfg $(INTAKE_RPM)
	livecd-creator -c $< -f intake --title=intake --product=intake

tftpboot/initrd0.img: intake.iso
	rm -fr tftpboot
	livecd-iso-to-pxeboot $<

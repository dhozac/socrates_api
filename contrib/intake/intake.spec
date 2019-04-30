%global ipmicfg_version 1.28.0_build.180302
%global debug_package %{nil}

Name: intake
Version: 0.1
Release: 1
Summary: intake gathers information about hardware
License: Apache
Source0: any-network.service
Source1: any-network.sh
Source2: haproxy.cfg
Source3: hp-apply.sh
Source4: hp-requires.py
Source10: intake.service
Source11: intake.sh
Source20: intake-controller.py
Source21: common.py
Source30: fw-updates.py
Source31: intake.py
Source32: oob-config.py
Source33: pxe-boot.py
Source34: raid-config.py
Source100: ftp://ftp.supermicro.com/utility/IPMICFG/IPMICFG_%{ipmicfg_version}.zip
Requires: lshw dmidecode python-dmidecode python-requests python-netifaces python-daemon haproxy lldpad dhclient ipmitool

%description
intake gathers information about hardware and reports it to a Socrates server.

%prep
%setup -c -T
unzip %{SOURCE100}

%build
%install
rm -fr %{buildroot}
mkdir -p %{buildroot}%{_libexecdir}/intake \
    %{buildroot}%{_sbindir} \
    %{buildroot}/usr/lib/systemd/system \
    %{buildroot}%{_sysconfdir}/haproxy \
    %{buildroot}/opt/ipmicfg

install -p -m0644 %{SOURCE0} %{buildroot}/usr/lib/systemd/system
install -p -m0755 %{SOURCE1} %{buildroot}%{_sbindir}/any-network
install -p -m0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/haproxy/haproxy.cfg.intake
install -p -m0755 %{SOURCE3} %{buildroot}%{_sbindir}/hp-apply
install -p -m0755 %{SOURCE4} %{buildroot}%{_sbindir}/hp-requires
install -p -m0644 %{SOURCE10} %{buildroot}/usr/lib/systemd/system
install -p -m0755 %{SOURCE11} %{buildroot}%{_sbindir}/intake
install -p -m0755 %{SOURCE20} %{buildroot}%{_sbindir}/intake-controller
install -p -m0644 %{SOURCE21} %{buildroot}%{_libexecdir}/intake/
install -p -m0755 %{SOURCE30} %{buildroot}%{_libexecdir}/intake/fw-updates
install -p -m0755 %{SOURCE31} %{buildroot}%{_libexecdir}/intake/intake
install -p -m0755 %{SOURCE32} %{buildroot}%{_libexecdir}/intake/oob-config
install -p -m0755 %{SOURCE33} %{buildroot}%{_libexecdir}/intake/pxe-boot
install -p -m0755 %{SOURCE34} %{buildroot}%{_libexecdir}/intake/raid-config
cp -p IPMICFG_1.28.0_build.180302/Linux/64bit/* %{buildroot}/opt/ipmicfg

%post
cp -p %{_sysconfdir}/haproxy/haproxy.cfg.intake %{_sysconfdir}/haproxy/haproxy.cfg

%files
%defattr(-,root,root,-)
%{_libexecdir}/intake/
%{_sbindir}/*
/usr/lib/systemd/system/*.service
%{_sysconfdir}/haproxy/*
/opt/ipmicfg/

ExclusiveArch: x86_64 aarch64

%define GITDATE        20230524
%define GITCOMMIT      ba91d0292e
%define TOOLCHAIN      GCC5
%define OPENSSL_VER    1.1.1k

%define DBXDATE        20230509

%define build_ovmf 0
%define build_aarch64 0
%ifarch x86_64
  %define build_ovmf 1
%endif
%ifarch aarch64
  %define build_aarch64 1
%endif

Name:       edk2
Version:    %{GITDATE}
Release:    4%{?dist}.2
Summary:    UEFI firmware for 64-bit virtual machines
License:    BSD-2-Clause-Patent and OpenSSL and MIT
URL:        http://www.tianocore.org

# The source tarball is created using following commands:
# COMMIT=ba91d0292e
# git archive --format=tar --prefix=edk2-$COMMIT/ $COMMIT \
# | xz -9ev >/tmp/edk2-$COMMIT.tar.xz
Source0:edk2-%{GITCOMMIT}.tar.xz
Source1: ovmf-whitepaper-c770f8c.txt
Source2: openssl-rhel-d00c3c5b8a9d6d3ea3dabfcafdf36afd61ba8bcc.tar.xz

# json description files
Source10: 50-edk2-aarch64-qcow2.json
Source11: 51-edk2-aarch64-raw.json
Source12: 52-edk2-aarch64-verbose-qcow2.json
Source13: 53-edk2-aarch64-verbose-raw.json

Source40: 30-edk2-ovmf-x64-sb-enrolled.json
Source41: 40-edk2-ovmf-x64-sb.json
Source43: 50-edk2-ovmf-x64-nosb.json
Source44: 60-edk2-ovmf-x64-amdsev.json
Source45: 60-edk2-ovmf-x64-inteltdx.json

# https://gitlab.com/kraxel/edk2-build-config
Source80: edk2-build.py
Source82: edk2-build.rhel-9

Source90: DBXUpdate-%{DBXDATE}.x64.bin

Patch0002: 0002-Remove-submodules.patch
Patch0003: 0003-MdeModulePkg-TerminalDxe-set-xterm-resolution-on-mod.patch
Patch0004: 0004-OvmfPkg-take-PcdResizeXterm-from-the-QEMU-command-li.patch
Patch0005: 0005-ArmVirtPkg-take-PcdResizeXterm-from-the-QEMU-command.patch
Patch0006: 0006-OvmfPkg-enable-DEBUG_VERBOSE-RHEL-only.patch
Patch0007: 0007-OvmfPkg-silence-DEBUG_VERBOSE-0x00400000-in-QemuVide.patch
Patch0008: 0008-ArmVirtPkg-silence-DEBUG_VERBOSE-0x00400000-in-QemuR.patch
Patch0009: 0009-OvmfPkg-QemuRamfbDxe-Do-not-report-DXE-failure-on-Aa.patch
Patch0010: 0010-OvmfPkg-silence-EFI_D_VERBOSE-0x00400000-in-NvmExpre.patch
Patch0011: 0011-OvmfPkg-QemuKernelLoaderFsDxe-suppress-error-on-no-k.patch
Patch0012: 0012-SecurityPkg-Tcg2Dxe-suppress-error-on-no-swtpm-in-si.patch
Patch0013: 0013-OvmfPkg-Remove-EbcDxe-RHEL-only.patch
Patch0014: 0014-OvmfPkg-Remove-VirtioGpu-device-driver-RHEL-only.patch
Patch0015: 0015-OvmfPkg-Remove-VirtioFsDxe-filesystem-driver-RHEL-on.patch
Patch0016: 0016-ArmVirtPkg-Remove-VirtioFsDxe-filesystem-driver-RHEL.patch
Patch0017: 0017-OvmfPkg-Remove-UdfDxe-filesystem-driver-RHEL-only.patch
Patch0018: 0018-ArmVirtPkg-Remove-UdfDxe-filesystem-driver-RHEL-only.patch
Patch0019: 0019-OvmfPkg-Remove-TftpDynamicCommand-from-shell-RHEL-on.patch
Patch0020: 0020-ArmVirtPkg-Remove-TftpDynamicCommand-from-shell-RHEL.patch
Patch0021: 0021-OvmfPkg-Remove-HttpDynamicCommand-from-shell-RHEL-on.patch
Patch0022: 0022-ArmVirtPkg-Remove-HttpDynamicCommand-from-shell-RHEL.patch
Patch0023: 0023-OvmfPkg-Remove-LinuxInitrdDynamicShellCommand-RHEL-o.patch
Patch0024: 0024-ArmVirtPkg-Remove-LinuxInitrdDynamicShellCommand-RHE.patch
Patch0025: 0025-recreate-import-redhat-directory.patch
Patch0026: 0026-CryptoPkg-OpensslLib-list-RHEL8-specific-OpenSSL-fil.patch
Patch0027: 0027-OvmfPkg-disable-dynamic-mmio-window-rhel-only.patch
Patch0028: 0028-ArmPkg-Disable-EFI_MEMORY_ATTRIBUTE_PROTOCOL-RH-only.patch
Patch0029: 0029-OvmfPkg-PciHotPlugInitDxe-Do-not-reserve-IO-ports-by.patch
# For RHEL-643 - add virtio serial support to armvirt
Patch30: edk2-ArmVirt-add-VirtioSerialDxe-to-ArmVirtQemu-builds.patch
# For RHEL-643 - add virtio serial support to armvirt
Patch31: edk2-ArmVirt-PlatformBootManagerLib-factor-out-IsVirtio.patch
# For RHEL-643 - add virtio serial support to armvirt
Patch32: edk2-ArmVirt-PlatformBootManagerLib-factor-out-IsVirtioPc.patch
# For RHEL-643 - add virtio serial support to armvirt
Patch33: edk2-ArmVirt-PlatformBootManagerLib-set-up-virtio-serial-.patch
# For RHEL-643 - add virtio serial support to armvirt
Patch34: edk2-OvmfPkg-VirtioSerialDxe-use-TPL_NOTIFY.patch
# For RHEL-643 - add virtio serial support to armvirt
Patch35: edk2-OvmfPkg-VirtioSerialDxe-Remove-noisy-debug-print-on-.patch
# For bz#2174749 - [edk2] re-enable dynamic mmio window
Patch36: edk2-OvmfPkg-PlatformInitLib-limit-phys-bits-to-46.patch
# For bz#2174749 - [edk2] re-enable dynamic mmio window
Patch37: edk2-Revert-OvmfPkg-disable-dynamic-mmio-window-rhel-only.patch
# For bz#2124143 - ovmf must consider max cpu count not boot cpu count for apic mode [rhel-9]
Patch38: edk2-UefiCpuPkg-MpInitLib-fix-apic-mode-for-cpu-hotplug.patch
# For RHEL-644 - enable gigabyte pages
Patch39: edk2-OvmfPkg-PlatformInitLib-check-PcdUse1GPageTable.patch
# For RHEL-644 - enable gigabyte pages
Patch40: edk2-OvmfPkg-OvmfPkgIa32X64-enable-1G-pages.patch
# For RHEL-644 - enable gigabyte pages
Patch41: edk2-OvmfPkg-MicrovmX64-enable-1G-pages.patch
# For bz#2190244 - [EDK2] [AMDSERVER 9.3 Bug] OVMF AP Creation Fixes
Patch42: edk2-OvmfPkg-AmdSev-fix-BdsPlatform.c-assertion-failure-d.patch
# For bz#2211060 - SEV-es guest randomly stuck at boot to hard drive screen from powerdown and boot again
Patch43: edk2-OvmfPkg-IoMmuDxe-add-locking-to-IoMmuAllocateBounceB.patch
# For bz#2218196 - Add vtpm devices with OVMF.amdsev.fd causes VM reset
Patch44: edk2-OvmfPkg-AmdSevDxe-Shim-Reboot-workaround-RHEL-only.patch
# For RHEL-9943 - [EDK2][AMDSERVER Bug] OvmfPkg/ResetVector: Fix assembler bit test flag check [rhel-9.3.0.z]
Patch45: edk2-OvmfPkg-ResetVector-Fix-assembler-bit-test-flag-chec.patch
# For RHEL-21996 - CVE-2023-45230 edk2: Buffer overflow in the DHCPv6 client via a long Server ID option [rhel-9.3.0.z]
Patch46: edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45230-Pa.patch
# For RHEL-21996 - CVE-2023-45230 edk2: Buffer overflow in the DHCPv6 client via a long Server ID option [rhel-9.3.0.z]
Patch47: edk2-NetworkPkg-Add-Unit-tests-to-CI-and-create-Host-Test.patch
# For RHEL-21996 - CVE-2023-45230 edk2: Buffer overflow in the DHCPv6 client via a long Server ID option [rhel-9.3.0.z]
Patch48: edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45230-Un.patch
# For RHEL-22005 - CVE-2023-45234 edk2: Buffer overflow when processing DNS Servers option in a DHCPv6 Advertise message [rhel-9.3.0.z]
Patch49: edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523.patch
# For RHEL-22005 - CVE-2023-45234 edk2: Buffer overflow when processing DNS Servers option in a DHCPv6 Advertise message [rhel-9.3.0.z]
Patch50: edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523p2.patch


# python3-devel and libuuid-devel are required for building tools.
# python3-devel is also needed for varstore template generation and
# verification with "ovmf-vars-generator".
BuildRequires:  python3-devel
BuildRequires:  libuuid-devel
BuildRequires:  /usr/bin/iasl
BuildRequires:  binutils gcc git gcc-c++ make
BuildRequires:  qemu-img

%if %{build_ovmf}
# Only OVMF includes 80x86 assembly files (*.nasm*).
BuildRequires:  nasm

# Only OVMF includes the Secure Boot feature, for which we need to separate out
# the UEFI shell.
BuildRequires:  dosfstools
BuildRequires:  mtools
BuildRequires:  xorriso

# secure boot enrollment
BuildRequires:  python3dist(virt-firmware) >= 23.4

# endif build_ovmf
%endif


%package ovmf
Summary:    UEFI firmware for x86_64 virtual machines
BuildArch:  noarch
Provides:   OVMF = %{version}-%{release}
Obsoletes:  OVMF < 20180508-100.gitee3198e672e2.el7

# OVMF includes the Secure Boot and IPv6 features; it has a builtin OpenSSL
# library.
Provides:   bundled(openssl) = %{OPENSSL_VER}
License:    BSD-2-Clause-Patent and OpenSSL

# URL taken from the Maintainers.txt file.
URL:        http://www.tianocore.org/ovmf/

%description ovmf
OVMF (Open Virtual Machine Firmware) is a project to enable UEFI support for
Virtual Machines. This package contains a sample 64-bit UEFI firmware for QEMU
and KVM.


%package aarch64
Summary:    UEFI firmware for aarch64 virtual machines
BuildArch:  noarch
Provides:   AAVMF = %{version}-%{release}
Obsoletes:  AAVMF < 20180508-100.gitee3198e672e2.el7

# need libvirt version with qcow2 support
Conflicts:  libvirt-daemon-driver-qemu < 9.2.0

# No Secure Boot for AAVMF yet, but we include OpenSSL for the IPv6 stack.
Provides:   bundled(openssl) = %{OPENSSL_VER}
License:    BSD-2-Clause-Patent and OpenSSL

# URL taken from the Maintainers.txt file.
URL:        https://github.com/tianocore/tianocore.github.io/wiki/ArmVirtPkg

%description aarch64
AAVMF (ARM Architecture Virtual Machine Firmware) is an EFI Development Kit II
platform that enables UEFI support for QEMU/KVM ARM Virtual Machines. This
package contains a 64-bit build.


%package tools
Summary:        EFI Development Kit II Tools
License:        BSD-2-Clause-Patent
URL:            https://github.com/tianocore/tianocore.github.io/wiki/BaseTools
%description tools
This package provides tools that are needed to
build EFI executables and ROMs using the GNU tools.

%package tools-doc
Summary:        Documentation for EFI Development Kit II Tools
BuildArch:      noarch
License:        BSD-2-Clause-Patent
URL:            https://github.com/tianocore/tianocore.github.io/wiki/BaseTools
%description tools-doc
This package documents the tools that are needed to
build EFI executables and ROMs using the GNU tools.

%description
EDK II is a modern, feature-rich, cross-platform firmware development
environment for the UEFI and PI specifications. This package contains sample
64-bit UEFI firmware builds for QEMU and KVM.

%prep
# We needs some special git config options that %%autosetup won't give us.
# We init the git dir ourselves, then tell %%autosetup not to blow it away.
%setup -q -n edk2-%{GITCOMMIT}
git init -q
git config core.whitespace cr-at-eol
git config am.keepcr true
# -T is passed to %%setup to not re-extract the archive
# -D is passed to %%setup to not delete the existing archive dir
%autosetup -T -D -n edk2-%{GITCOMMIT} -S git_am

cp -a -- %{SOURCE1} .
cp -a -- %{SOURCE10} %{SOURCE11} %{SOURCE12} %{SOURCE13} .
cp -a -- %{SOURCE40} %{SOURCE41} %{SOURCE43} %{SOURCE44} %{SOURCE45} .
cp -a -- %{SOURCE80} %{SOURCE82} .
cp -a -- %{SOURCE90} .
tar -C CryptoPkg/Library/OpensslLib -a -f %{SOURCE2} -x

# Done by %setup, but we do not use it for the auxiliary tarballs
chmod -Rf a+rX,u+w,g-w,o-w .

%build

build_iso() {
  dir="$1"
  UEFI_SHELL_BINARY=${dir}/Shell.efi
  ENROLLER_BINARY=${dir}/EnrollDefaultKeys.efi
  UEFI_SHELL_IMAGE=uefi_shell.img
  ISO_IMAGE=${dir}/UefiShell.iso

  UEFI_SHELL_BINARY_BNAME=$(basename -- "$UEFI_SHELL_BINARY")
  UEFI_SHELL_SIZE=$(stat --format=%s -- "$UEFI_SHELL_BINARY")
  ENROLLER_SIZE=$(stat --format=%s -- "$ENROLLER_BINARY")

  # add 1MB then 10% for metadata
  UEFI_SHELL_IMAGE_KB=$((
    (UEFI_SHELL_SIZE + ENROLLER_SIZE + 1 * 1024 * 1024) * 11 / 10 / 1024
  ))

  # create non-partitioned FAT image
  rm -f -- "$UEFI_SHELL_IMAGE"
  mkdosfs -C "$UEFI_SHELL_IMAGE" -n UEFI_SHELL -- "$UEFI_SHELL_IMAGE_KB"

  # copy the shell binary into the FAT image
  export MTOOLS_SKIP_CHECK=1
  mmd   -i "$UEFI_SHELL_IMAGE"                       ::efi
  mmd   -i "$UEFI_SHELL_IMAGE"                       ::efi/boot
  mcopy -i "$UEFI_SHELL_IMAGE"  "$UEFI_SHELL_BINARY" ::efi/boot/bootx64.efi
  mcopy -i "$UEFI_SHELL_IMAGE"  "$ENROLLER_BINARY"   ::
  mdir  -i "$UEFI_SHELL_IMAGE"  -/                   ::

  # build ISO with FAT image file as El Torito EFI boot image
  mkisofs -input-charset ASCII -J -rational-rock \
    -e "$UEFI_SHELL_IMAGE" -no-emul-boot \
    -o "$ISO_IMAGE" "$UEFI_SHELL_IMAGE"
}

export EXTRA_OPTFLAGS="%{optflags}"
export EXTRA_LDFLAGS="%{__global_ldflags}"
export RELEASE_DATE="$(echo %{GITDATE} | sed -e 's|\(....\)\(..\)\(..\)|\2/\3/\1|')"

touch OvmfPkg/AmdSev/Grub/grub.efi   # dummy

%if %{build_ovmf}
./edk2-build.py --config edk2-build.rhel-9 -m ovmf --release-date "$RELEASE_DATE"
build_iso RHEL-9/ovmf
virt-fw-vars --input   RHEL-9/ovmf/OVMF_VARS.fd \
             --output  RHEL-9/ovmf/OVMF_VARS.secboot.fd \
             --set-dbx DBXUpdate-%{DBXDATE}.x64.bin \
             --enroll-redhat --secure-boot
%endif

%if %{build_aarch64}
./edk2-build.py --config edk2-build.rhel-9 -m armvirt --release-date "$RELEASE_DATE"
for raw in */aarch64/*.raw; do
    qcow2="${raw%.raw}.qcow2"
    qemu-img convert -f raw -O qcow2 -o cluster_size=4096 -S 4096 "$raw" "$qcow2"
done
%endif

%install

cp -a OvmfPkg/License.txt License.OvmfPkg.txt
cp -a CryptoPkg/Library/OpensslLib/openssl/LICENSE LICENSE.openssl
mkdir -p %{buildroot}%{_datadir}/qemu/firmware

# install the tools
mkdir -p %{buildroot}%{_bindir} \
         %{buildroot}%{_datadir}/%{name}/Conf \
         %{buildroot}%{_datadir}/%{name}/Scripts
install BaseTools/Source/C/bin/* \
        %{buildroot}%{_bindir}
install BaseTools/BinWrappers/PosixLike/LzmaF86Compress \
        %{buildroot}%{_bindir}
install BaseTools/BuildEnv \
        %{buildroot}%{_datadir}/%{name}
install BaseTools/Conf/*.template \
        %{buildroot}%{_datadir}/%{name}/Conf
install BaseTools/Scripts/GccBase.lds \
        %{buildroot}%{_datadir}/%{name}/Scripts

mkdir -p %{buildroot}%{_datadir}/%{name}
cp -av RHEL-9/* %{buildroot}%{_datadir}/%{name}

%if %{build_ovmf}
mkdir -p %{buildroot}%{_datadir}/OVMF

ln -s ../%{name}/ovmf/OVMF_CODE.secboot.fd %{buildroot}%{_datadir}/OVMF/
ln -s ../%{name}/ovmf/OVMF_VARS.fd         %{buildroot}%{_datadir}/OVMF/
ln -s ../%{name}/ovmf/OVMF_VARS.secboot.fd %{buildroot}%{_datadir}/OVMF/
ln -s ../%{name}/ovmf/UefiShell.iso        %{buildroot}%{_datadir}/OVMF/
ln -s OVMF_CODE.fd %{buildroot}%{_datadir}/%{name}/ovmf/OVMF_CODE.cc.fd

install -m 0644 \
        30-edk2-ovmf-x64-sb-enrolled.json \
        40-edk2-ovmf-x64-sb.json \
        50-edk2-ovmf-x64-nosb.json \
        60-edk2-ovmf-x64-amdsev.json \
        60-edk2-ovmf-x64-inteltdx.json \
        %{buildroot}%{_datadir}/qemu/firmware

# endif build_ovmf
%endif

%if %{build_aarch64}
mkdir -p %{buildroot}%{_datadir}/AAVMF

ln -s ../%{name}/aarch64/QEMU_EFI-pflash.raw \
  %{buildroot}%{_datadir}/AAVMF/AAVMF_CODE.verbose.fd
ln -s ../%{name}/aarch64/QEMU_EFI-silent-pflash.raw \
  %{buildroot}%{_datadir}/AAVMF/AAVMF_CODE.fd
ln -s ../%{name}/aarch64/vars-template-pflash.raw \
  %{buildroot}%{_datadir}/AAVMF/AAVMF_VARS.fd

install -m 0644 \
        50-edk2-aarch64-qcow2.json \
        51-edk2-aarch64-raw.json \
        52-edk2-aarch64-verbose-qcow2.json \
        53-edk2-aarch64-verbose-raw.json \
        %{buildroot}%{_datadir}/qemu/firmware

# endif build_aarch64
%endif

%check

%global common_files \
  %%license License.txt License.OvmfPkg.txt License-History.txt LICENSE.openssl \
  %%dir %%{_datadir}/%%{name}/ \
  %%dir %%{_datadir}/qemu \
  %%dir %%{_datadir}/qemu/firmware

%if %{build_ovmf}
%files ovmf
%common_files
%doc OvmfPkg/README
%doc ovmf-whitepaper-c770f8c.txt
%dir %{_datadir}/OVMF/
%dir %{_datadir}/%{name}/ovmf/
%{_datadir}/%{name}/ovmf/OVMF_CODE.fd
%{_datadir}/%{name}/ovmf/OVMF_CODE.cc.fd
%{_datadir}/%{name}/ovmf/OVMF_CODE.secboot.fd
%{_datadir}/%{name}/ovmf/OVMF_VARS.fd
%{_datadir}/%{name}/ovmf/OVMF_VARS.secboot.fd
%{_datadir}/%{name}/ovmf/OVMF.amdsev.fd
%{_datadir}/%{name}/ovmf/OVMF.inteltdx.fd
%{_datadir}/%{name}/ovmf/UefiShell.iso
%{_datadir}/OVMF/OVMF_CODE.secboot.fd
%{_datadir}/OVMF/OVMF_VARS.fd
%{_datadir}/OVMF/OVMF_VARS.secboot.fd
%{_datadir}/OVMF/UefiShell.iso
%{_datadir}/%{name}/ovmf/Shell.efi
%{_datadir}/%{name}/ovmf/EnrollDefaultKeys.efi
%{_datadir}/qemu/firmware/30-edk2-ovmf-x64-sb-enrolled.json
%{_datadir}/qemu/firmware/40-edk2-ovmf-x64-sb.json
%{_datadir}/qemu/firmware/50-edk2-ovmf-x64-nosb.json
%{_datadir}/qemu/firmware/60-edk2-ovmf-x64-amdsev.json
%{_datadir}/qemu/firmware/60-edk2-ovmf-x64-inteltdx.json
# endif build_ovmf
%endif

%if %{build_aarch64}
%files aarch64
%common_files
%dir %{_datadir}/AAVMF/
%dir %{_datadir}/%{name}/aarch64/
%{_datadir}/%{name}/aarch64/QEMU_EFI-pflash.*
%{_datadir}/%{name}/aarch64/QEMU_EFI-silent-pflash.*
%{_datadir}/%{name}/aarch64/vars-template-pflash.*
%{_datadir}/AAVMF/AAVMF_CODE.verbose.fd
%{_datadir}/AAVMF/AAVMF_CODE.fd
%{_datadir}/AAVMF/AAVMF_VARS.fd
%{_datadir}/%{name}/aarch64/QEMU_EFI.fd
%{_datadir}/%{name}/aarch64/QEMU_EFI.silent.fd
%{_datadir}/%{name}/aarch64/QEMU_VARS.fd
%{_datadir}/qemu/firmware/50-edk2-aarch64-qcow2.json
%{_datadir}/qemu/firmware/51-edk2-aarch64-raw.json
%{_datadir}/qemu/firmware/52-edk2-aarch64-verbose-qcow2.json
%{_datadir}/qemu/firmware/53-edk2-aarch64-verbose-raw.json
# endif build_aarch64
%endif

%files tools
%license License.txt
%license License-History.txt
%{_bindir}/DevicePath
%{_bindir}/EfiRom
%{_bindir}/GenCrc32
%{_bindir}/GenFfs
%{_bindir}/GenFv
%{_bindir}/GenFw
%{_bindir}/GenSec
%{_bindir}/LzmaCompress
%{_bindir}/LzmaF86Compress
%{_bindir}/TianoCompress
%{_bindir}/VfrCompile
%{_bindir}/VolInfo
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/BuildEnv
%{_datadir}/%{name}/Conf
%{_datadir}/%{name}/Scripts

%files tools-doc
%doc BaseTools/UserManuals/*.rtf


%changelog
* Tue Feb 20 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20230524-4.el9_3.2
- edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523.patch [RHEL-22005]
- edk2-NetworkPkg-UefiPxeBcDxe-SECURITY-PATCH-CVE-2023-4523p2.patch [RHEL-22005]
- Resolves: RHEL-22005
  (CVE-2023-45234 edk2: Buffer overflow when processing DNS Servers option in a DHCPv6 Advertise message [rhel-9.3.0.z])

* Wed Feb 14 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20230524-4.el9_3.1
- edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45230-Pa.patch [RHEL-21996]
- edk2-NetworkPkg-Add-Unit-tests-to-CI-and-create-Host-Test.patch [RHEL-21996]
- edk2-NetworkPkg-Dhcp6Dxe-SECURITY-PATCH-CVE-2023-45230-Un.patch [RHEL-21996]
- Resolves: RHEL-21996
  (CVE-2023-45230 edk2: Buffer overflow in the DHCPv6 client via a long Server ID option [rhel-9.3.0.z])

* Mon Oct 09 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20230524-4
- edk2-OvmfPkg-ResetVector-Fix-assembler-bit-test-flag-chec.patch [RHEL-9943]
- Resolves: RHEL-9943
  ([EDK2][AMDSERVER Bug] OvmfPkg/ResetVector: Fix assembler bit test flag check [rhel-9.3.0.z])

* Thu Aug 24 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20230524-3
- edk2-OvmfPkg-AmdSev-fix-BdsPlatform.c-assertion-failure-d.patch [bz#2190244]
- edk2-OvmfPkg-IoMmuDxe-add-locking-to-IoMmuAllocateBounceB.patch [bz#2211060]
- edk2-OvmfPkg-AmdSevDxe-Shim-Reboot-workaround-RHEL-only.patch [bz#2218196]
- Resolves: bz#2190244
  ([EDK2] [AMDSERVER 9.3 Bug] OVMF AP Creation Fixes)
- Resolves: bz#2211060
  (SEV-es guest randomly stuck at boot to hard drive screen from powerdown and boot again)
- Resolves: bz#2218196
  (Add vtpm devices with OVMF.amdsev.fd causes VM reset)

* Mon Jul 10 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20230524-2
- edk2-ArmVirt-add-VirtioSerialDxe-to-ArmVirtQemu-builds.patch [RHEL-643]
- edk2-ArmVirt-PlatformBootManagerLib-factor-out-IsVirtio.patch [RHEL-643]
- edk2-ArmVirt-PlatformBootManagerLib-factor-out-IsVirtioPc.patch [RHEL-643]
- edk2-ArmVirt-PlatformBootManagerLib-set-up-virtio-serial-.patch [RHEL-643]
- edk2-OvmfPkg-VirtioSerialDxe-use-TPL_NOTIFY.patch [RHEL-643]
- edk2-OvmfPkg-VirtioSerialDxe-Remove-noisy-debug-print-on-.patch [RHEL-643]
- edk2-OvmfPkg-PlatformInitLib-limit-phys-bits-to-46.patch [bz#2174749]
- edk2-Revert-OvmfPkg-disable-dynamic-mmio-window-rhel-only.patch [bz#2174749]
- edk2-UefiCpuPkg-MpInitLib-fix-apic-mode-for-cpu-hotplug.patch [bz#2124143]
- edk2-OvmfPkg-PlatformInitLib-check-PcdUse1GPageTable.patch [RHEL-644]
- edk2-OvmfPkg-OvmfPkgIa32X64-enable-1G-pages.patch [RHEL-644]
- edk2-OvmfPkg-MicrovmX64-enable-1G-pages.patch [RHEL-644]
- Resolves: RHEL-643
  (add virtio serial support to armvirt)
- Resolves: bz#2174749
  ([edk2] re-enable dynamic mmio window)
- Resolves: bz#2124143
  (ovmf must consider max cpu count not boot cpu count for apic mode [rhel-9])
- Resolves: RHEL-644
  (enable gigabyte pages)

* Tue Jun 27 2023 Oliver Steffen <osteffen@redhat.com> - 20230524-1
- Rebase to edk2-stable202305 tag [RHEL-585]
  Resolves: RHEL-585
  ([rhel-9.3] rebase EDK2 to edk2-stable202305)

* Mon May 22 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20230301gitf80f052277c8-5
- edk2-dbx-update-2023-05-09-black-lotus-edition.patch [RHEL-470]
- edk2-json-descriptors-explicitly-set-mode-split.patch [RHEL-469]
- Resolves: RHEL-470
  (edk2: update variable store with latest dbx updates (may 9, black lotus edition))
- Resolves: RHEL-469
  (explicitly set mode = split in firmware json description files)

* Tue May 16 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20230301gitf80f052277c8-4
- edk2-OvmfPkg-Clarify-invariants-for-NestedInterruptTplLib.patch [bz#2189136]
- edk2-OvmfPkg-Relax-assertion-that-interrupts-do-not-occur.patch [bz#2189136]
- Resolves: bz#2189136
  (windows 11 installation broken with edk2-20230301gitf80f052277c8-1.el9)

* Mon May 08 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20230301gitf80f052277c8-3
- edk2-add-aarch64-qcow2-images.patch [bz#2186754]
- edk2-update-json-files.patch [bz#2186754]
- edk2-add-libvirt-version-conflict.patch [bz#2186754]
- edk2-add-dbx-update-blob-rh-only.patch [RHEL-377]
- edk2-spec-apply-dbx-update-rh-only.patch [RHEL-377]
- Resolves: bz#2186754
  (edk2: Add firmware images in qcow2 format)
- Resolves: RHEL-377
  (edk2: ship secure build variable store with latest dbx updates)

* Wed Apr 05 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20230301gitf80f052277c8-2
- edk2-build-script-update.patch [bz#2183230]
- edk2-PcdDxeNxMemoryProtectionPolicy-update.patch [bz#2183230]
- Resolves: bz#2183230
  ([edk2] Instruction abort exception when booting a VM)

* Wed Mar 22 2023 Miroslav Rezanina <mrezanin@redaht.com> - 20230301gitf80f052277c8-1
- Rebase to edk2-stable202302 [RHEL-266]
- Resolves: RHEL-266
  (rebase edk2 to 2023-02 stable tag)

* Fri Mar 17 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-9
- edk2-remove-amd-sev-feature-flag-from-secure-boot-builds-.patch [bz#2169247]
- Resolves: bz#2169247
  ([edk2] Install a sev guest with enrolled secure boot failed)

* Fri Mar 10 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-8
- edk2-OvmfPkg-disable-dynamic-mmio-window-rhel-only.patch [bz#2174605]
- Resolves: bz#2174605
  ([EDK2] disable dynamic mmio window)

* Tue Feb 21 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-7
- edk2-Revert-MdeModulePkg-TerminalDxe-add-other-text-resol.patch [bz#2162307]
- Resolves: bz#2162307
  (Broken GRUB output on a serial console)

* Mon Feb 13 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-6
- edk2-update-build-script-rhel-only.patch [bz#2168046]
- edk2-update-build-config-rhel-only.patch [bz#2168046]
- edk2-add-release-date-to-builds-rh-only.patch [bz#2168046]
- edk2-openssl-update.patch [bz#2164534 bz#2164550 bz#2164565 bz#2164583]
- edk2-rh-openssl-add-crypto-bn-rsa_sup_mul.c-to-file-list.patch [bz#2164534 bz#2164550 bz#2164565 bz#2164583]
- Resolves: bz#2168046
  ([SVVP] job 'Check SMBIOS Table Specific Requirements' failed on win2022)
- Resolves: bz#2164534
  (CVE-2023-0286 edk2: openssl: X.400 address type confusion in X.509 GeneralName [rhel-9])
- Resolves: bz#2164550
  (CVE-2022-4304 edk2: openssl: timing attack in RSA Decryption implementation [rhel-9])
- Resolves: bz#2164565
  (CVE-2023-0215 edk2: openssl: use-after-free following BIO_new_NDEF [rhel-9])
- Resolves: bz#2164583
  (CVE-2022-4450 edk2: openssl: double free after calling PEM_read_bio_ex [rhel-9])

* Mon Feb 06 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-5
- edk2-Revert-ArmVirtPkg-ArmVirtQemu-enable-initial-ID-map-.patch [bz#2157656]
- Resolves: bz#2157656
  ([edk2] [aarch64] Unable to initialize EFI firmware when using edk2-aarch64-20221207gitfff6d81270b5-1.el9 in some hardwares)

* Wed Jan 18 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-4
- edk2-ArmVirt-don-t-use-unaligned-CopyMem-on-NOR-flash.patch [bz#2158173]
- Resolves: bz#2158173
  ([aarch64][numa] Failed to create 2 numa nodes in some hardwares)

* Mon Jan 16 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-3
- edk2-OvmfPkg-VirtNorFlashDxe-map-flash-memory-as-uncachea.patch [bz#2158173]
- edk2-MdePkg-Remove-Itanium-leftover-data-structure-RH-onl.patch [bz#1983086]
- Resolves: bz#2158173
  ([aarch64][numa] Failed to create 2 numa nodes in some hardwares)
- Resolves: bz#1983086
  (Assertion failure when creating 1024 VCPU VM: [...]UefiCpuPkg/CpuMpPei/CpuBist.c(186): !EFI_ERROR (Status))

* Thu Jan 05 2023 Miroslav Rezanina <mrezanin@redhat.com> - 20221207gitfff6d81270b5-2
- edk2-use-rpm-build-flags-rh-only.patch [RHEL-177]
- Resolves: RHEL-177
  (Enable GNU_RELRO security protection)

* Thu Dec 15 2022 Camilla Conte <cconte@redhat.com> - 20221207gitfff6d81270b5-1
- Rebase to edk2-stable202211 tag
  Resolves: RHEL-119
  (rebase edk2 to edk2-stable202211)
- Resolves: RHEL-75
  (edk2 builds should show the build version)
- Resolves: bz#2132951
  (edk2: Sort traditional virtualization builds before Confidential Computing builds)

* Mon Nov 21 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220826gitba0e0e4c6a-2
- edk2-MdeModulePkg-PiSmmCore-SmmEntryPoint-underflow-CVE-2.patch [bz#1989857]
- Resolves: bz#1989857
  (CVE-2021-38578 edk2: integer underflow in SmmEntryPoint function leads to potential SMM privilege escalation [rhel-9.0])

* Tue Oct 11 2022 Miroslav Rezanina <mrezanin@redhat.com> -  0220826gitba0e0e4c6a-1
- Rebase to edk2-stable202208 tag [RHELX-59]
  Resolves: RHELX-59
  (rebase edk2 to 2022-08 stable tag)

* Fri Sep 16 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220526git16779ede2d36-4
- edk2-OvmfPkg-QemuVideoDxe-fix-bochs-mode-init.patch [RHELX-58]
- Resolves: RHELX-58
  (Guest console turns black with uefi rhel guests and stdvga)

* Mon Aug 01 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220526git16779ede2d36-3
- edk2-openssl-jump-to-8.7.0-branch-2022-07-22.patch [bz#2074843]
- edk2-ovmf-vars-generator-Use-max-cpu.patch [bz#2111567]
- Resolves: bz#2074843
  (edk2: sync openssl sources with rhel openssl rpm)
- Resolves: bz#2111567
  (EDK2 build stuck with qemu-kvm-7.0.0-8.el9 or newer)

* Fri Jun 24 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220526git16779ede2d36-2
- edk2-OvmfPkg-Update-target-machines-config.patch [bz#2090752]
- Resolves: bz#2090752
  (Add RHEL 8.5, 8,6 and 9.x machine types to firmware descriptor files 50-edk2-ovmf-{amdsev,cc}.json)

* Mon Jun 13 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220526git16779ede2d36-1
- Rebase to edk2-stable-202205 [bz#2074831]
- Resolves: bz#2074831
  (rebase edk2 to May 2022 release (edk2-stable202205))

* Thu May 26 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220221gitb24306f15d-2
- edk2-Revert-ArmVirtPkg-Remove-QemuRamfbDxe-display-device.patch [bz#2087220]
- edk2-Revert-OvmfPkg-Remove-QemuRamfbDxe-display-device-dr.patch [bz#2087220]
- Resolves: bz#2087220
  (VNC display show "Guest has not initialized the display" when using ramfb + ovmf)

* Thu Mar 31 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220221gitb24306f15d-1
- Rebae to edk-stable-202202 [bz#2056910]
- Resolves: bz#2056910
  ([rebase] update edk2 to feb '22 release (edk2-stable202202xx))

* Wed Mar 23 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220126gitbb1bba3d77-4
- edk2-Revert-OvmfPkg-Remove-NvmExpressDxe-device-driver-RH.patch [bz#2044196]
- edk2-Revert-ArmVirtPkg-Remove-NvmExpressDxe-device-driver.patch [bz#2044196]
- Resolves: bz#2044196
  (RFE: [nvme-vfio] The virt-install interface throws info "Failed to set new efi boot target"  when install a vm on a hostdev nvme disk)

* Wed Feb 23 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220126gitbb1bba3d77-3
- edk2-spec-build-amdsev-variant.patch [bz#2054661]
- edk2-OvmfPkg-AmdSev-SecretPei-Mark-SEV-launch-secret-area.patch [bz#2041755]
- Resolves: bz#2054661
  (RFE:  Support measured AMD SEV boot with kernel/initrd/cmdline in OVMF)
- Resolves: bz#2041755
  (Mark SEV launch secret area as reserved)

* Tue Feb 08 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220126gitbb1bba3d77-2
- edk2-OvmfPkg-remove-unused-TPM-options-from-MicrovmX64.ds.patch [bz#1935497]
- edk2-OvmfPkg-move-tcg-configuration-to-dsc-and-fdf-includ.patch [bz#1935497]
- edk2-OvmfPkg-drop-TPM_CONFIG_ENABLE.patch [bz#1935497]
- edk2-OvmfPkg-create-Tcg12ConfigPei.inf.patch [bz#1935497]
- edk2-OvmfPkg-rework-TPM-configuration.patch [bz#1935497]
- edk2-spec-adapt-specfile-to-build-option-changes-disable-.patch [bz#1935497]
- Resolves: bz#1935497
  (edk2  implements and/or uses the deprecated MD5 and SHA-1 algorithms by default)

* Tue Feb 01 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20220126gitbb1bba3d77-1
- Rebase to latest upstream release [bz#2018388]
- Resolves: bz#2018388
  ([rebase] update edk2 to nov '21 release (edk2-stable202111xx))

* Fri Jan 14 2022 Miroslav Rezanina <mrezanin@redhat.com> - 20210527gite1999b264f1f-8
- edk2-Revert-advertise-OpenSSL-on-TianoCore-splash-screen-.patch [bz#2027286]
- Resolves: bz#2027286
  (Remove the customized boot splash logo patch)

* Mon Nov 01 2021 Miroslav Rezanina <mrezanin@redhat.com> - 20210527gite1999b264f1f-7
- edk2-fix-tpm-build-options.patch [bz#2000396]
- Resolves: bz#2000396
  ([aarch64][RHEL9] The lack of TPMFinalLog in efi causes the tpm self-test in the guest to fail)

* Mon Aug 09 2021 Mohan Boddu <mboddu@redhat.com> - 20210527gite1999b264f1f-6
- Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
  Related: rhbz#1991688

* Fri Aug 06 2021 Miroslav Rezanina <mrezanin@redhat.com> - 20210527gite1999b264f1f-5
- edk2-MdeModulePkg-PartitionDxe-Ignore-PMBR-BootIndicator-.patch [bz#1988760]
- Resolves: bz#1988760
  (edk2 does not ignore PMBR protective record BootIndicator as required by UEFI spec)

* Fri Jul 30 2021 Miroslav Rezanina <mrezanin@redhat.com> - 20210527gite1999b264f1f-4
- edk2-spec-remove-Group-and-defattr.patch [bz#1983789]
- edk2-spec-Add-BuildRequires-make.patch [bz#1983789]
- edk2-spec-don-t-conditionalize-package-definitions.patch [bz#1983789]
- edk2-spec-Use-autosetup-with-our-required-git-config-opti.patch [bz#1983789]
- edk2-spec-Replace-ifarch-else-conditionals-with-build_XXX.patch [bz#1983789]
- edk2-spec-Move-D-TPM_ENABLE-to-common-CC_FLAGS.patch [bz#1983789]
- edk2-spec-Add-qemu_package-and-qemu_binary.patch [bz#1983789]
- edk2-spec-Remove-extra-true-at-end-of-check.patch [bz#1983789]
- edk2-spec-Move-check-to-between-install-and-files.patch [bz#1983789]
- edk2-spec-Add-qosb_testing-macro.patch [bz#1983789]
- edk2-spec-Split-out-build_iso-function.patch [bz#1983789]
- edk2-spec-Replace-RPM_BUILD_ROOT-with-buildroot.patch [bz#1983789]
- edk2-spec-Use-make_build-macro.patch [bz#1983789]
- edk2-spec-Factor-out-OVMF_FLAGS-and-OVMF_SB_FLAGS.patch [bz#1983789]
- edk2-spec-Don-t-put-build-output-in-the-top-directory.patch [bz#1983789]
- edk2-spec-Centralize-non-firmware-install-files-at-the-to.patch [bz#1983789]
- Resolves: bz#1983789
  (Make spec easier to share with Fedora)

* Mon Jul 12 2021 Miroslav Rezanina <mrezanin@redhat.com> - 20210527gite1999b264f1f-3
- edk2-OvmfPkg-Remove-PrintDxe-RHEL-only.patch [bz#1967747]
- edk2-OvmfPkg-Remove-EbcDxe-RHEL-only.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-EbcDxe-RHEL-only.patch [bz#1967747]
- edk2-OvmfPkg-Remove-VirtioGpu-device-driver-RHEL-only.patch [bz#1967747]
- edk2-OvmfPkg-Remove-QemuRamfbDxe-display-device-driver-RH.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-QemuRamfbDxe-display-device-driver.patch [bz#1967747]
- edk2-OvmfPkg-Remove-NvmExpressDxe-device-driver-RHEL-only.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-NvmExpressDxe-device-driver-RHEL-o.patch [bz#1967747]
- edk2-OvmfPkg-Remove-VirtioFsDxe-filesystem-driver-RHEL-on.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-VirtioFsDxe-filesystem-driver-RHEL.patch [bz#1967747]
- edk2-OvmfPkg-Remove-UdfDxe-filesystem-driver-RHEL-only.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-UdfDxe-filesystem-driver-RHEL-only.patch [bz#1967747]
- edk2-OvmfPkg-Remove-TftpDynamicCommand-from-shell-RHEL-on.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-TftpDynamicCommand-from-shell-RHEL.patch [bz#1967747]
- edk2-OvmfPkg-Remove-HttpDynamicCommand-from-shell-RHEL-on.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-HttpDynamicCommand-from-shell-RHEL.patch [bz#1967747]
- edk2-OvmfPkg-Remove-LinuxInitrdDynamicShellCommand-RHEL-o.patch [bz#1967747]
- edk2-ArmVirtPkg-Remove-LinuxInitrdDynamicShellCommand-RHE.patch [bz#1967747]
- edk2-OvmfPkg-Remove-Xen-Drivers-RHEL-only.patch [bz#1967747]
- Resolves: bz#1967747
  (edk2: review features and drivers shipped in RHEL)

* Fri Jul 02 2021 Miroslav Rezanina <mrezanin@redhat.com> - 20210527gite1999b264f1f-2
- edk2-NetworkPkg-IScsiDxe-wrap-IScsiCHAP-source-files-to-8.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-simplify-ISCSI_CHAP_AUTH_DATA.In.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-clean-up-ISCSI_CHAP_AUTH_DATA.Ou.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-clean-up-library-class-dependenc.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-fix-potential-integer-overflow-i.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-assert-that-IScsiBinToHex-always.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-reformat-IScsiHexToBin-leading-c.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-fix-IScsiHexToBin-hex-parsing.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-fix-IScsiHexToBin-buffer-overflo.patch [bz#1961100]
- edk2-NetworkPkg-IScsiDxe-check-IScsiHexToBin-return-value.patch [bz#1961100]
- edk2-redhat-build-UefiShell.iso-with-xorriso-rather-than-.patch [bz#1971840]
- Resolves: bz#1961100
  (edk2: remote buffer overflow in IScsiHexToBin function in NetworkPkg/IScsiDxe [rhel-9.0])
- Resolves: bz#1971840
  (Please replace genisoimage with xorriso)

* Wed Jun 23 2021 Miroslav Rezanina <mrezanin@redhat.com> - 20210527gite1999b264f1f-1
- Rebase to edk2-stable202105 [bz#1938254]
- Sync edk2-MdeModulePkg-LzmaCustomDecompressLib-catch-4GB-uncom.patch from RHEL-8
- Sync edk2-redhat-add-OVMF-binary-that-will-support-SEV-ES.patch from RHEL-8
- Resolves: bz#1938254
  ((edk2-rebase-rhel-9.0) - rebase edk2 to edk2-stable202105 for RHEL-9-Beta)

* Fri Jan 08 2021 Miroslav Rezanina <mrezanin@redhat.com> - 20200602gitca407c7246bf-1.el9
- Include fixes to build in RHEL 9 environment (bz#1906468)
- Resolves: bz#1906468
  ([RHEL9][FTBFS] edk2 FTBFS on Red Hat Enterprise Linux 9.0.0 Alpha)

* Mon Nov 23 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20200602gitca407c7246bf-4.el8
- edk2-OvmfPkg-SmmControl2Dxe-negotiate-ICH9_LPC_SMI_F_CPU_.patch [bz#1849177]
- edk2-OvmfPkg-CpuHotplugSmm-fix-CPU-hotplug-race-just-befo.patch [bz#1849177]
- edk2-OvmfPkg-CpuHotplugSmm-fix-CPU-hotplug-race-just-afte.patch [bz#1849177]
- edk2-CryptoPkg-OpensslLib-Upgrade-OpenSSL-to-1.1.1g.patch [bz#1893806]
- edk2-redhat-bump-OpenSSL-dist-git-submodule-to-1.1.1g-RHE.patch [bz#1893806]
- Resolves: bz#1849177
  (OVMF: negotiate "SMI on VCPU hotplug" with QEMU)
- Resolves: bz#1893806
  (attempt advancing RHEL8 edk2's OpenSSL submodule to RHEL8 OpenSSL 1.1.1g (or later))

* Mon Aug 10 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20200602gitca407c7246bf-3.el8
- edk2-UefiCpuPkg-PiSmmCpuDxeSmm-pause-in-WaitForSemaphore-.patch [bz#1861718]
- Resolves: bz#1861718
  (Very slow boot when overcommitting CPU)

* Wed Jun 24 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20200602gitca407c7246bf-2.el8
- edk2-OvmfPkg-QemuKernelLoaderFsDxe-suppress-error-on-no-k.patch [bz#1844682]
- edk2-OvmfPkg-GenericQemuLoadImageLib-log-Not-Found-at-INF.patch [bz#1844682]
- edk2-SecurityPkg-Tcg2Dxe-suppress-error-on-no-swtpm-in-si.patch [bz#1844682]
- Resolves: bz#1844682
  (silent build of edk2-aarch64 logs DEBUG_ERROR messages that don't actually report serious errors)

* Sat Jun 13 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20200602gitca407c7246bf-1.el8
- Rebase to edk2-stable202005 [bz#1817035]
- Resolves: bz#1817035
  ((edk2-rebase-rhel-8.3) - rebase edk2 to upstream tag edk2-stable202005 for RHEL-8.3)

* Fri Mar 27 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-9.el8
- edk2-OvmfPkg-QemuVideoDxe-unbreak-secondary-vga-and-bochs.patch [bz#1806359]
- Resolves: bz#1806359
  (bochs-display cannot show graphic wihout driver attach)

* Tue Feb 18 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-8.el8
- edk2-MdeModulePkg-Enable-Disable-S3BootScript-dynamically.patch [bz#1801274]
- edk2-MdeModulePkg-PiDxeS3BootScriptLib-Fix-potential-nume.patch [bz#1801274]
- Resolves: bz#1801274
  (CVE-2019-14563 edk2: numeric truncation in MdeModulePkg/PiDxeS3BootScriptLib [rhel-8])

* Tue Feb 11 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-7.el8
- edk2-SecurityPkg-Fix-spelling-errors-PARTIAL-PICK.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-simplify-Ver.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-remove-else-.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-keep-PE-COFF.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-narrow-down-.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-fix-retval-o.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-remove-super.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-unnest-AddIm.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-eliminate-St.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-fix-retval-f.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-fix-imgexec-.patch [bz#1751993]
- edk2-SecurityPkg-DxeImageVerificationHandler-fix-defer-vs.patch [bz#1751993]
- Resolves: bz#1751993
  (DxeImageVerificationLib handles "DENY execute on security violation" like "DEFER execute on security violation" [rhel8])

* Tue Jan 21 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-6.el8
- edk2-UefiCpuPkg-PiSmmCpuDxeSmm-fix-2M-4K-page-splitting-r.patch [bz#1789335]
- Resolves: bz#1789335
  (VM with edk2 can't boot when setting memory with '-m 2001')

* Thu Jan 16 2020 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-5.el8
- edk2-MdeModulePkg-UefiBootManagerLib-log-reserved-mem-all.patch [bz#1789797]
- edk2-NetworkPkg-HttpDxe-fix-32-bit-truncation-in-HTTPS-do.patch [bz#1789797]
- Resolves: bz#1789797
  (Backport upstream patch series: "UefiBootManagerLib, HttpDxe: tweaks for large HTTP(S) downloads" to improve HTTP(S) Boot experience with large (4GiB+) files)

* Wed Dec 11 2019 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-4.el8
- edk2-redhat-set-guest-RAM-size-to-768M-for-SB-varstore-te.patch [bz#1778301]
- edk2-redhat-re-enable-Secure-Boot-varstore-template-verif.patch [bz#1778301]
- Resolves: bz#1778301
  (re-enable Secure Boot (varstore template) verification in %check)

* Thu Dec 05 2019 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-3.el8
- Update used openssl version [bz#1616029]
- Resolves: bz#1616029
  (rebuild edk2 against the final RHEL-8.2.0 version of OpenSSL-1.1.1)

* Mon Dec 02 2019 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-2.el8
- edk2-MdePkg-Include-Protocol-Tls.h-Add-the-data-type-of-E.patch [bz#1536624]
- edk2-CryptoPkg-TlsLib-Add-the-new-API-TlsSetVerifyHost-CV.patch [bz#1536624]
- edk2-CryptoPkg-Crt-turn-strchr-into-a-function-CVE-2019-1.patch [bz#1536624]
- edk2-CryptoPkg-Crt-satisfy-inet_pton.c-dependencies-CVE-2.patch [bz#1536624]
- edk2-CryptoPkg-Crt-import-inet_pton.c-CVE-2019-14553.patch [bz#1536624]
- edk2-CryptoPkg-TlsLib-TlsSetVerifyHost-parse-IP-address-l.patch [bz#1536624]
- edk2-NetworkPkg-TlsDxe-Add-the-support-of-host-validation.patch [bz#1536624]
- edk2-NetworkPkg-HttpDxe-Set-the-HostName-for-the-verifica.patch [bz#1536624]
- edk2-redhat-enable-HTTPS-Boot.patch [bz#1536624]
- Resolves: bz#1536624
  (HTTPS enablement in OVMF)

* Fri Nov 29 2019 Miroslav Rezanina <mrezanin@redhat.com> - 20190829git37eef91017ad-1.el8
- Rebase to edk2-stable201908 [bz#1748180]
- Resolves: bz#1748180
  ((edk2-rebase-rhel-8.2) - rebase edk2 to upstream tag edk2-stable201908 for RHEL-8.2)

* Mon Aug 05 2019 Miroslav Rezanina <mrezanin@redhat.com> - 20190308git89910a39dcfd-6.el8
- edk2-ArmVirtPkg-silence-DEBUG_VERBOSE-masking-0x00400000-.patch [bz#1714446]
- edk2-OvmfPkg-QemuRamfbDxe-Do-not-report-DXE-failure-on-Aa.patch [bz#1714446]
- edk2-ArmPkg-DebugPeCoffExtraActionLib-debugger-commands-a.patch [bz#1714446]
- Resolves: bz#1714446
  (edk2-aarch64 silent build is not silent enough)

* Tue Jul 02 2019 Miroslav Rezanina <mrezanin@redhat.com> - 20190308git89910a39dcfd-5.el8
- edk2-redhat-add-D-TPM2_ENABLE-to-the-edk2-ovmf-build-flag.patch [bz#1693205]
- Resolves: bz#1693205
  (edk2: Enable TPM2 support)

* Tue Jun 11 2019 Miroslav Rezanina <mrezanin@redhat.com> - 20190308git89910a39dcfd-4.el8
- edk2-OvmfPkg-raise-the-PCIEXBAR-base-to-2816-MB-on-Q35.patch [bz#1666941]
- edk2-OvmfPkg-PlatformPei-set-32-bit-UC-area-at-PciBase-Pc.patch [bz#1666941]
- Resolves: bz#1666941
  (UEFI guest cannot boot into os when setting some special memory size)

* Tue Apr 09 2019 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20190308git89910a39dcfd-2.el8
- edk2-redhat-provide-firmware-descriptor-meta-files.patch [bz#1600230]
- Resolves: bz#1600230
  ([RHEL 8.1] RFE: provide firmware descriptor meta-files for the edk2-ovmf and edk2-aarch64 firmware images)

* Mon Apr 08 2019 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20190308git89910a39dcfd-1.el8
- Rebase to edk2-20190308git89910a39dcfd

* Mon Jan 21 2019 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20180508gitee3198e672e2-9.el8
- edk2-BaseTools-Fix-UEFI-and-Tiano-Decompression-logic-iss.patch [bz#1662184]
- edk2-MdePkg-BaseUefiDecompressLib-Fix-UEFI-Decompression-.patch [bz#1662184]
- edk2-IntelFrameworkModulePkg-Fix-UEFI-and-Tiano-Decompres.patch [bz#1662184]
- edk2-git-Use-HTTPS-support.patch []
- Resolves: bz#1662184
  (backport fix for (theoretical?) regression introduced by earlier CVE fixes)

* Wed Nov 21 2018 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20180508gitee3198e672e2-8.el8
- edk2-NetworkPkg-UefiPxeBcDxe-Add-EXCLUSIVE-attribute-when.patch [bz#1643377]
- Resolves: bz#1643377
  (Exception when grubx64.efi used for UEFI netboot)

* Tue Nov 06 2018 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20180508gitee3198e672e2-5.el8
- edk2-MdeModulePkg-Variable-Fix-Timestamp-zeroing-issue-on.patch [bz#1641436]
- edk2-MdePkg-Add-more-checker-in-UefiDecompressLib-to-acce.patch [bz#1641449 bz#1641453 bz#1641464 bz#1641469]
- edk2-IntelFrameworkModulePkg-Add-more-checker-in-UefiTian.patch [bz#1641453 bz#1641464 bz#1641469]
- edk2-BaseTools-Add-more-checker-in-Decompress-algorithm-t.patch [bz#1641445 bz#1641453 bz#1641464 bz#1641469]
- Resolves: bz#1641436
  (CVE-2018-3613 edk2: Logic error in MdeModulePkg in EDK II firmware allows for privilege escalation by authenticated users [rhel-8])
- Resolves: bz#1641445
  (CVE-2017-5731 edk2: Privilege escalation via processing of malformed files in TianoCompress.c [rhel-8])
- Resolves: bz#1641449
  (CVE-2017-5732 edk2: Privilege escalation via processing of malformed files in BaseUefiDecompressLib.c [rhel-8])
- Resolves: bz#1641453
  (CVE-2017-5733 edk2: Privilege escalation via heap-based buffer overflow in MakeTable() function [rhel-8])
- Resolves: bz#1641464
  (CVE-2017-5734 edk2: Privilege escalation via stack-based buffer overflow in MakeTable() function [rhel-8])
- Resolves: bz#1641469
  (CVE-2017-5735 edk2: Privilege escalation via heap-based buffer overflow in Decode() function [rhel-8])

* Tue Sep 04 2018 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20180508gitee3198e672e2-5.el8
- edk2-BaseTools-footer.makefile-expand-BUILD_CFLAGS-last-f.patch [bz#1607906]
- edk2-BaseTools-header.makefile-remove-c-from-BUILD_CFLAGS.patch [bz#1607906]
- edk2-BaseTools-Source-C-split-O2-to-BUILD_OPTFLAGS.patch [bz#1607906]
- edk2-BaseTools-Source-C-take-EXTRA_OPTFLAGS-from-the-call.patch [bz#1607906]
- edk2-BaseTools-Source-C-take-EXTRA_LDFLAGS-from-the-calle.patch [bz#1607906]
- edk2-BaseTools-VfrCompile-honor-EXTRA_LDFLAGS.patch [bz#1607906]
- edk2-redhat-inject-the-RPM-compile-and-link-options-to-th.patch [bz#1607906]
- Resolves: bz#1607906
  (edk2-tools: Does not use RPM build flags)

* Wed Aug 08 2018 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20180508gitee3198e672e2-4.el8
- edk2-redhat-provide-virtual-bundled-OpenSSL-in-edk2-ovmf-.patch [bz#1607801]
- Resolves: bz#1607801
  (add 'Provides: bundled(openssl) = 1.1.0h' to the spec file)

* Tue Jul 24 2018 Danilo Cesar Lemes de Paula <ddepaula@redhat.com> - 20180508gitee3198e672e2-3.el8
- edk2-redhat-Provide-and-Obsolete-OVMF-and-AAVMF.patch [bz#1596148]
- edk2-ArmVirtPkg-unify-HttpLib-resolutions-in-ArmVirt.dsc..patch [bz#1536627]
- edk2-ArmVirtPkg-ArmVirtQemu-enable-the-IPv6-stack.patch [bz#1536627]
- edk2-advertise-OpenSSL-due-to-IPv6-enablement-too-RHEL-on.patch [bz#1536627]
- edk2-redhat-add-D-NETWORK_IP6_ENABLE-to-the-build-flags.patch [bz#1536627]
- edk2-redhat-update-license-fields-and-files-in-the-spec-f.patch [bz#1536627]
- Resolves: bz#1536627
  (IPv6 enablement in OVMF)
- Resolves: bz#1596148
  (restore Provides/Obsoletes macros for OVMF and AAVMF, from RHEL-8 Alpha)

* Tue Jul 10 2018 Danilo C. L. de Paula <ddepaula@redhat.com> - 20180508gitee3198e672e2-2.el8
- Rebase edk2 on top of 20180508gitee3198e672e2

* Fri Jun 08 2018 Miroslav Rezanina <mrezanin@redhat.com> - 20180508-2.gitee3198e672e2
- OvmfPkg/PlatformBootManagerLib: connect consoles unconditionally [bz#1577546]
- build OVMF varstore template with SB enabled / certs enrolled [bz#1561128]
- connect Virtio RNG devices again [bz#1579518]
- Resolves: bz#1577546
  (no input consoles connected under certain circumstances)
- Resolves: bz#1561128
  (OVMF Secure boot enablement (enrollment of default keys))
- Resolves: bz#1579518
  (EFI_RNG_PROTOCOL no longer produced for virtio-rng)
* Wed Dec 06 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20171011-4.git92d07e48907f.el7
- ovmf-MdeModulePkg-Core-Dxe-log-informative-memprotect-msg.patch [bz#1520485]
- ovmf-MdeModulePkg-BdsDxe-fall-back-to-a-Boot-Manager-Menu.patch [bz#1515418]
- Resolves: bz#1515418
  (RFE: Provide diagnostics for failed boot)
- Resolves: bz#1520485
  (AAVMF: two new messages with silent build)

* Fri Dec 01 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20171011-3.git92d07e48907f.el7
- ovmf-UefiCpuPkg-CpuDxe-Fix-multiple-entries-of-RT_CODE-in.patch [bz#1518308]
- ovmf-MdeModulePkg-DxeCore-Filter-out-all-paging-capabilit.patch [bz#1518308]
- ovmf-MdeModulePkg-Core-Merge-memory-map-after-filtering-p.patch [bz#1518308]
- Resolves: bz#1518308
  (UEFI memory map regression (runtime code entry splitting) introduced by c1cab54ce57c)

* Mon Nov 27 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20171011-2.git92d07e48907f.el7
- ovmf-MdeModulePkg-Bds-Remove-assertion-in-BmCharToUint.patch [bz#1513632]
- ovmf-MdeModulePkg-Bds-Check-variable-name-even-if-OptionN.patch [bz#1513632]
- ovmf-MdeModulePkg-PciBus-Fix-bug-that-PCI-BUS-claims-too-.patch [bz#1514105]
- ovmf-OvmfPkg-make-it-a-proper-BASE-library.patch [bz#1488247]
- ovmf-OvmfPkg-create-a-separate-PlatformDebugLibIoPort-ins.patch [bz#1488247]
- ovmf-OvmfPkg-save-on-I-O-port-accesses-when-the-debug-por.patch [bz#1488247]
- ovmf-OvmfPkg-enable-DEBUG_VERBOSE-RHEL-only.patch [bz#1488247]
- ovmf-OvmfPkg-silence-EFI_D_VERBOSE-0x00400000-in-QemuVide.patch [bz#1488247]
- ovmf-OvmfPkg-silence-EFI_D_VERBOSE-0x00400000-in-NvmExpre.patch [bz#1488247]
- ovmf-Revert-redhat-introduce-separate-silent-and-verbose-.patch [bz#1488247]
- Resolves: bz#1488247
  (make debug logging no-op unless a debug console is active)
- Resolves: bz#1513632
  ([RHEL-ALT 7.5] AAVMF fails to boot after setting BootNext)
- Resolves: bz#1514105
  (backport edk2 commit 6e3287442774 so that PciBusDxe not over-claim resources)

* Wed Oct 18 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20171011-1.git92d07e48907f.el7
- Rebase to 92d07e48907f [bz#1469787]
- Resolves: bz#1469787
  ((ovmf-rebase-rhel-7.5) Rebase OVMF for RHEL-7.5)
- Resolves: bz#1434740
  (OvmfPkg/PciHotPlugInitDxe: don't reserve IO space when IO support is disabled)
- Resolves: bz#1434747
  ([Q35] code12 error when hotplug x710 device in win2016)
- Resolves: bz#1447027
  (Guest cannot boot with 240 or above vcpus when using ovmf)
- Resolves: bz#1458192
  ([Q35] recognize "usb-storage" devices in XHCI ports)
- Resolves: bz#1468526
  (>1TB RAM support)
- Resolves: bz#1488247
  (provide "OVMF_CODE.secboot.verbose.fd" for log capturing; silence "OVMF_CODE.secboot.fd")
- Resolves: bz#1496170
  (Inconsistent MOR control variables exposed by OVMF, breaks Windows Device Guard)

* Fri May 12 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20170228-5.gitc325e41585e3.el7
- ovmf-OvmfPkg-EnrollDefaultKeys-update-SignatureOwner-GUID.patch [bz#1443351]
- ovmf-OvmfPkg-EnrollDefaultKeys-expose-CertType-parameter-.patch [bz#1443351]
- ovmf-OvmfPkg-EnrollDefaultKeys-blacklist-empty-file-in-db.patch [bz#1443351]
- ovmf-OvmfPkg-introduce-the-FD_SIZE_IN_KB-macro-build-flag.patch [bz#1443351]
- ovmf-OvmfPkg-OvmfPkg.fdf.inc-extract-VARS_LIVE_SIZE-and-V.patch [bz#1443351]
- ovmf-OvmfPkg-introduce-4MB-flash-image-mainly-for-Windows.patch [bz#1443351]
- ovmf-OvmfPkg-raise-max-variable-size-auth-non-auth-to-33K.patch [bz#1443351]
- ovmf-OvmfPkg-PlatformPei-handle-non-power-of-two-spare-si.patch [bz#1443351]
- ovmf-redhat-update-local-build-instructions-with-D-FD_SIZ.patch [bz#1443351]
- ovmf-redhat-update-OVMF-build-commands-with-D-FD_SIZE_4MB.patch [bz#1443351]
- Resolves: bz#1443351
  ([svvp][ovmf] job "Secure Boot Logo Test" failed  with q35&ovmf)

* Fri Apr 28 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20170228-4.gitc325e41585e3.el7
- ovmf-ShellPkg-Shell-clean-up-bogus-member-types-in-SPLIT_.patch [bz#1442908]
- ovmf-ShellPkg-Shell-eliminate-double-free-in-RunSplitComm.patch [bz#1442908]
- Resolves: bz#1442908
  (Guest hang when running a wrong command in Uefishell)

* Tue Apr 04 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20170228-3.gitc325e41585e3.el7
- ovmf-ArmVirtPkg-FdtClientDxe-supplement-missing-EFIAPI-ca.patch [bz#1430262]
- ovmf-ArmVirtPkg-ArmVirtPL031FdtClientLib-unconditionally-.patch [bz#1430262]
- ovmf-MdeModulePkg-RamDiskDxe-fix-C-string-literal-catenat.patch [bz#1430262]
- ovmf-EmbeddedPkg-introduce-EDKII-Platform-Has-ACPI-GUID.patch [bz#1430262]
- ovmf-EmbeddedPkg-introduce-PlatformHasAcpiLib.patch [bz#1430262]
- ovmf-EmbeddedPkg-introduce-EDKII-Platform-Has-Device-Tree.patch [bz#1430262]
- ovmf-ArmVirtPkg-add-PlatformHasAcpiDtDxe.patch [bz#1430262]
- ovmf-ArmVirtPkg-enable-AcpiTableDxe-and-EFI_ACPI_TABLE_PR.patch [bz#1430262]
- ovmf-ArmVirtPkg-FdtClientDxe-install-DT-as-sysconfig-tabl.patch [bz#1430262]
- ovmf-ArmVirtPkg-PlatformHasAcpiDtDxe-don-t-expose-DT-if-Q.patch [bz#1430262]
- ovmf-ArmVirtPkg-remove-PURE_ACPI_BOOT_ENABLE-and-PcdPureA.patch [bz#1430262]
- Resolves: bz#1430262
  (AAVMF: forward QEMU's DT to the guest OS only if ACPI payload is unavailable)

* Mon Mar 27 2017 Miroslav Rezanina <mrezanin@redhat.com> - 20170228-2.gitc325e41585e3.el7
- ovmf-MdeModulePkg-Core-Dxe-downgrade-CodeSegmentCount-is-.patch [bz#1433428]
- Resolves: bz#1433428
  (AAVMF: Fix error message during ARM guest VM installation)

* Wed Mar 08 2017 Laszlo Ersek <lersek@redhat.com> - ovmf-20170228-1.gitc325e41585e3.el7
- Rebase to upstream c325e41585e3 [bz#1416919]
- Resolves: bz#1373812
  (guest boot from network even set 'boot order=1' for virtio disk with OVMF)
- Resolves: bz#1380282
  (Update OVMF to openssl-1.0.2k-hobbled)
- Resolves: bz#1412313
  (select broadcast SMI if available)
- Resolves: bz#1416919
  (Rebase OVMF for RHEL-7.4)
- Resolves: bz#1426330
  (disable libssl in CryptoPkg)

* Mon Sep 12 2016 Laszlo Ersek <lersek@redhat.com> - ovmf-20160608b-1.git988715a.el7
- rework downstream-only commit dde83a75b566 "setup the tree for the secure
  boot feature (RHEL only)", excluding patent-encumbered files from the
  upstream OpenSSL 1.0.2g tarball [bz#1374710]
- rework downstream-only commit dfc3ca1ee509 "CryptoPkg/OpensslLib: Upgrade
  OpenSSL version to 1.0.2h", excluding patent-encumbered files from the
  upstream OpenSSL 1.0.2h tarball [bz#1374710]

* Thu Aug 04 2016 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20160608-3.git988715a.el7
- ovmf-MdePkg-PCI-Add-missing-PCI-PCIE-definitions.patch [bz#1332408]
- ovmf-ArmPlatformPkg-NorFlashDxe-accept-both-non-secure-an.patch [bz#1353494]
- ovmf-ArmVirtPkg-ArmVirtQemu-switch-secure-boot-build-to-N.patch [bz#1353494]
- ovmf-ArmPlatformPkg-NorFlashAuthenticatedDxe-remove-this-.patch [bz#1353494]
- ovmf-ArmVirtPkg-add-FDF-definition-for-empty-varstore.patch [bz#1353494]
- ovmf-redhat-package-the-varstore-template-produced-by-the.patch [bz#1353494]
- ovmf-ArmVirtPkg-Re-add-the-Driver-Health-Manager.patch [bz#1353494]
- ovmf-ArmVirtPkg-HighMemDxe-allow-patchable-PCD-for-PcdSys.patch [bz#1353494]
- ovmf-ArmVirtPkg-ArmVirtQemuKernel-make-ACPI-support-AARCH.patch [bz#1353494]
- ovmf-ArmVirtPkg-align-ArmVirtQemuKernel-with-ArmVirtQemu.patch [bz#1353494]
- ovmf-ArmVirtPkg-ArmVirtQemu-factor-out-shared-FV.FvMain-d.patch [bz#1353494]
- ovmf-ArmVirtPkg-factor-out-Rules-FDF-section.patch [bz#1353494]
- ovmf-ArmVirtPkg-add-name-GUIDs-to-FvMain-instances.patch [bz#1353494]
- ovmf-OvmfPkg-add-a-Name-GUID-to-each-Firmware-Volume.patch [bz#1353494]
- ovmf-OvmfPkg-PlatformBootManagerLib-remove-stale-FvFile-b.patch [bz#1353494]
- ovmf-MdePkg-IndustryStandard-introduce-EFI_PCI_CAPABILITY.patch [bz#1332408]
- ovmf-MdeModulePkg-PciBusDxe-look-for-the-right-capability.patch [bz#1332408]
- ovmf-MdeModulePkg-PciBusDxe-recognize-hotplug-capable-PCI.patch [bz#1332408]
- ovmf-OvmfPkg-add-PciHotPlugInitDxe.patch [bz#1332408]
- ovmf-ArmPkg-ArmGicLib-manage-GICv3-SPI-state-at-the-distr.patch [bz#1356655]
- ovmf-ArmVirtPkg-PlatformBootManagerLib-remove-stale-FvFil.patch [bz#1353494]
- ovmf-OvmfPkg-EnrollDefaultKeys-assign-Status-before-readi.patch [bz#1356913]
- ovmf-OvmfPkg-EnrollDefaultKeys-silence-VS2015x86-warning-.patch [bz#1356913]
- ovmf-CryptoPkg-update-openssl-to-ignore-RVCT-3079.patch [bz#1356184]
- ovmf-CryptoPkg-Fix-typos-in-comments.patch [bz#1356184]
- ovmf-CryptoPkg-BaseCryptLib-Avoid-passing-NULL-ptr-to-fun.patch [bz#1356184]
- ovmf-CryptoPkg-BaseCryptLib-Init-the-content-of-struct-Ce.patch [bz#1356184]
- ovmf-CryptoPkg-OpensslLib-Upgrade-OpenSSL-version-to-1.0..patch [bz#1356184]
- Resolves: bz#1332408
  (Q35 machine can not hot-plug scsi controller under switch)
- Resolves: bz#1353494
  ([OVMF] "EFI Internal Shell" should be removed from "Boot Manager")
- Resolves: bz#1356184
  (refresh embedded OpenSSL to 1.0.2h)
- Resolves: bz#1356655
  (AAVMF: stop accessing unmapped gicv3 registers)
- Resolves: bz#1356913
  (fix use-without-initialization in EnrollDefaultKeys.efi)

* Tue Jul 12 2016 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20160608-2.git988715a.el7
- ovmf-ArmPkg-ArmGicV3Dxe-configure-all-interrupts-as-non-s.patch [bz#1349407]
- ovmf-ArmVirtPkg-PlatformBootManagerLib-Postpone-the-shell.patch [bz#1353689]
- Resolves: bz#1349407
  (AArch64: backport fix to run over gicv3 emulation)
- Resolves: bz#1353689
  (AAVMF: Drops to shell with uninitialized NVRAM file)

* Thu Jun 9 2016 Laszlo Ersek <lersek@redhat.com> - ovmf-20160608-1.git988715a.el7
- Resolves: bz#1341733
  (prevent SMM stack overflow in OVMF while enrolling certificates in "db")
- Resolves: bz#1257882
  (FEAT: support to boot from virtio 1.0 modern devices)
- Resolves: bz#1333238
  (Q35 machine can not boot up successfully with more than 3 virtio-scsi
  storage controller under switch)
- Resolves: bz#1330955
  (VM can not be booted up from hard disk successfully when with a passthrough
  USB stick)

* Thu May 19 2016 Laszlo Ersek <lersek@redhat.com> - ovmf-20160419-2.git90bb4c5.el7
- Submit scratch builds from the exploded tree again to
  supp-rhel-7.3-candidate, despite FatPkg being OSS at this point; see
  bz#1329559.

* Wed Apr 20 2016 Laszlo Ersek <lersek@redhat.com> - ovmf-20160419-1.git90bb4c5.el7
- FatPkg is under the 2-clause BSDL now; "ovmf" has become OSS
- upgrade to openssl-1.0.2g
- Resolves: bz#1323363
  (remove "-D SECURE_BOOT_ENABLE" from AAVMF)
- Resolves: bz#1257882
  (FEAT: support to boot from virtio 1.0 modern devices)
- Resolves: bz#1308678
  (clearly separate SB-less, SMM-less OVMF binary from SB+SMM OVMF binary)

* Fri Feb 19 2016 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20160202-2.gitd7c0dfa.el7
- ovmf-restore-TianoCore-splash-logo-without-OpenSSL-advert.patch [bz#1308678]
- ovmf-OvmfPkg-ArmVirtPkg-show-OpenSSL-less-logo-without-Se.patch [bz#1308678]
- ovmf-OvmfPkg-simplify-VARIABLE_STORE_HEADER-generation.patch [bz#1308678]
- ovmf-redhat-bring-back-OVMF_CODE.fd-but-without-SB-and-wi.patch [bz#1308678]
- ovmf-redhat-rename-OVMF_CODE.smm.fd-to-OVMF_CODE.secboot..patch [bz#1308678]

* Tue Feb 2 2016 Laszlo Ersek <lersek@redhat.com> - ovmf-20160202-1.gitd7c0dfa.el7
- rebase to upstream d7c0dfa
- update OpenSSL to 1.0.2e (upstream)
- update FatPkg to SVN r97 (upstream)
- drive NVMe devices (upstream)
- resize xterm on serial console mode change, when requested with
  -fw_cfg name=opt/(ovmf|aavmf)/PcdResizeXterm,string=y
  (downstream)
- Resolves: bz#1259395
  (revert / roll back AAVMF fix for BZ 1188054)
- Resolves: bz#1202819
  (OVMF: secure boot limitations)
- Resolves: bz#1182495
  (OVMF rejects iPXE oprom when Secure Boot is enabled)

* Thu Nov 5 2015 Laszlo Ersek <lersek@redhat.com> - ovmf-20151104-1.gitb9ffeab.el7
- rebase to upstream b9ffeab
- Resolves: bz#1207554
  ([AAVMF] AArch64: populate SMBIOS)
- Resolves: bz#1270279
  (AAVMF: output improvements)

* Thu Jun 25 2015 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20150414-2.gitc9e5618.el7
- ovmf-OvmfPkg-PlatformPei-set-SMBIOS-entry-point-version-d.patch [bz#1232876]
- Resolves: bz#1232876
  (OVMF should install a version 2.8 SMBIOS entry point)

* Sat Apr 18 2015 Laszlo Ersek <lersek@redhat.com> - 20150414-1.gitc9e5618.el7
- rebase from upstream 9ece15a to c9e5618
- adapt .gitignore files
- update to openssl-0.9.8zf
- create Logo-OpenSSL.bmp rather than modifying Logo.bmp in-place
- update to FatPkg SVN r93 (git 8ff136aa)
- drop the following downstream-only patches (obviated by upstream
  counterparts):
  "tools_def.template: use forward slash with --add-gnu-debuglink (RHEL only)"
  "tools_def.template: take GCC48 prefixes from environment (RHEL only)"
  "OvmfPkg: set video resolution of text setup to 640x480 (RHEL only)"
  "OvmfPkg: resolve OrderedCollectionLib with base red-black tree instance"
  "OvmfPkg: AcpiPlatformDxe: actualize QemuLoader.h comments"
  "OvmfPkg: AcpiPlatformDxe: remove current ACPI table loader"
  "OvmfPkg: AcpiPlatformDxe: implement QEMU's full ACPI table loader interface"
  "OvmfPkg: QemuVideoDxe: fix querying of QXL's drawable buffer size"
  "OvmfPkg: disable stale fork of SecureBootConfigDxe"
  "OvmfPkg: SecureBootConfigDxe: remove stale fork"
  "Try to read key strike even when ..."
  "OvmfPkg: BDS: remove dead call to PlatformBdsEnterFrontPage()"
  "OvmfPkg: BDS: drop useless return statement"
  "OvmfPkg: BDS: don't overwrite the BDS Front Page timeout"
  "OvmfPkg: BDS: optimize second argument in PlatformBdsEnterFrontPage() call"
  'OvmfPkg: BDS: drop superfluous "connect first boot option" logic'
  "OvmfPkg: BDS: drop custom boot timeout, revert to IntelFrameworkModulePkg's"
  "Add comments to clarify mPubKeyStore buffer MemCopy. ..."
  "MdeModulePkg/SecurityPkg Variable: Add boundary check..."
  "OvmfPkg: AcpiPlatformDxe: make dependency on PCI enumeration explicit"
  "MdePkg: UefiScsiLib: do not encode LUN in CDB for READ and WRITE"
  "MdePkg: UefiScsiLib: do not encode LUN in CDB for other SCSI commands"
- merge downstream AAVMF patch "adapt packaging to Arm64", which forces us to
  rename the main package from "OVMF" to "ovmf"
- drop the following ARM BDS specific tweaks (we'll only build the Intel BDS):
  "ArmPlatformPkg/Bds: generate ESP Image boot option if user pref is unset
   (Acadia)"
  "ArmPlatformPkg/Bds: check for other defaults too if user pref is unset
   (Acadia)"
  "ArmPlatformPkg/ArmVirtualizationPkg: auto-detect boot path (Acadia)"
  "ArmPlatformPkg/Bds: initialize ConIn/ConOut/ErrOut before connecting
   terminals"
  "ArmPlatformPkg/Bds: let FindCandidate() search all filesystems"
  "ArmPlatformPkg/Bds: FindCandidateOnHandle(): log full device path"
  "ArmPlatformPkg/Bds: fall back to Boot Menu when no default option was found"
  "ArmPlatformPkg/Bds: always connect drivers before looking at boot options"
- drop patch "ArmPlatformPkg/ArmVirtualizationPkg: enable DEBUG_VERBOSE (Acadia
  only)", obsoleted by fixed bug 1197141
- tweak patch "write up build instructions (for interactive, local development)
  (RHELSA)". The defaults in "BaseTools/Conf/target.template", ie.
  ACTIVE_PLATFORM and TARGET_ARCH, are set for OVMF / X64. The AAVMF build
  instructions now spell out the necessary override options (-p and -a,
  respectively).
- extend patch "build FAT driver from source (RHELSA)" to the Xen build as well
  (only for consistency; we don't build for Xen).
- drop the following downstream-only AAVMF patches, due to the 77d5dac ->
  c9e5618 AAVMF rebase & join:
  "redhat/process-rh-specific.sh: fix check for hunk-less filtered patches"
  "redhat/process-rh-specific.sh: suppress missing files in final 'rm'"
  "ArmVirtualizationQemu: build UEFI shell from source (Acadia only)"
  "MdePkg: UefiScsiLib: do not encode LUN in CDB for READ and WRITE"
  "MdePkg: UefiScsiLib: do not encode LUN in CDB for other SCSI commands"
  "ArmVirtualizationPkg: work around cache incoherence on KVM affecting DTB"
  "Changed build target to supp-rhel-7.1-candidate"
  "ArmVirtualizationPkg: VirtFdtDxe: forward FwCfg addresses from DTB to PCDs"
  "ArmVirtualizationPkg: introduce QemuFwCfgLib instance for DXE drivers"
  "ArmVirtualizationPkg: clone PlatformIntelBdsLib from ArmPlatformPkg"
  "ArmVirtualizationPkg: PlatformIntelBdsLib: add basic policy"
  "OvmfPkg: extract QemuBootOrderLib"
  "OvmfPkg: QemuBootOrderLib: featurize PCI-like device path translation"
  "OvmfPkg: introduce VIRTIO_MMIO_TRANSPORT_GUID"
  "ArmVirtualizationPkg: VirtFdtDxe: use dedicated VIRTIO_MMIO_TRANSPORT_GUID"
  "OvmfPkg: QemuBootOrderLib: widen ParseUnitAddressHexList() to UINT64"
  "OvmfPkg: QemuBootOrderLib: OFW-to-UEFI translation for virtio-mmio"
  "ArmVirtualizationPkg: PlatformIntelBdsLib: adhere to QEMU's boot order"
  "ArmVirtualizationPkg: identify "new shell" as builtin shell for Intel BDS"
  "ArmVirtualizationPkg: Intel BDS: load EFI-stubbed Linux kernel from fw_cfg"
  'Revert "ArmVirtualizationPkg: work around cache incoherence on KVM affecting
   DTB"'
  "OvmfPkg: QemuBootOrderLib: expose QEMU's "-boot menu=on[, splash-time=N]""
  "OvmfPkg: PlatformBdsLib: get front page timeout from QEMU"
  "ArmVirtualizationPkg: PlatformIntelBdsLib: get front page timeout from QEMU"
  "ArmPkg: ArmArchTimerLib: clean up comments"
  "ArmPkg: ArmArchTimerLib: use edk2-conformant (UINT64 * UINT32) / UINT32"
  "ArmPkg: ArmArchTimerLib: conditionally rebase to actual timer frequency"
  "ArmVirtualizationQemu: ask the hardware for the timer frequency"
  "ArmPkg: DebugPeCoffExtraActionLib: debugger commands are not errors"
  "ArmPlatformPkg: PEIM startup is not an error"
  "ArmVirtualizationPkg: PlatformIntelBdsLib: lack of QEMU kernel is no error"
  "ArmVirtualizationPkg: expose debug message bitmask on build command line"
- tweak patch "rebase to upstream 77d5dac (Acadia only)": update spec changelog
  only
- tweak patch "spec: build AAVMF with the Intel BDS driver (RHELSA only)":
  apply "-D INTEL_BDS" to manual build instructions in redhat/README too
- tweak patch "spec: build and install verbose and silent (default) AAVMF
  binaries": apply DEBUG_PRINT_ERROR_LEVEL setting to interactive build
  instructions in redhat/README too
- install OVMF whitepaper as part of the OVMF build's documentation
- Resolves: bz#1211337
  (merge AAVMF into OVMF)
- Resolves: bz#1206523
  ([AAVMF] fix missing cache maintenance)

* Fri Mar 06 2015 Miroslav Rezanina <mrezanin@redhat.com> - AAVMF-20141113-5.git77d5dac.el7_1
- aavmf-ArmPkg-DebugPeCoffExtraActionLib-debugger-commands-a.patch [bz#1197141]
- aavmf-ArmPlatformPkg-PEIM-startup-is-not-an-error.patch [bz#1197141]
- aavmf-ArmVirtualizationPkg-PlatformIntelBdsLib-lack-of-QEM.patch [bz#1197141]
- aavmf-ArmVirtualizationPkg-expose-debug-message-bitmask-on.patch [bz#1197141]
- aavmf-spec-build-and-install-verbose-and-silent-default-AA.patch [bz#1197141]
- Resolves: bz#1197141
  (create silent & verbose builds)

* Tue Feb 10 2015 Miroslav Rezanina <mrezanin@redhat.com> - AAVMF-20141113-4.git77d5dac.el7
- aavmf-ArmPkg-ArmArchTimerLib-clean-up-comments.patch [bz#1188247]
- aavmf-ArmPkg-ArmArchTimerLib-use-edk2-conformant-UINT64-UI.patch [bz#1188247]
- aavmf-ArmPkg-ArmArchTimerLib-conditionally-rebase-to-actua.patch [bz#1188247]
- aavmf-ArmVirtualizationQemu-ask-the-hardware-for-the-timer.patch [bz#1188247]
- aavmf-ArmPkg-TimerDxe-smack-down-spurious-timer-interrupt-.patch [bz#1188054]
- Resolves: bz#1188054
  (guest reboot (asked from within AAVMF) regressed in 3.19.0-0.rc5.58.aa7a host kernel)
- Resolves: bz#1188247
  (backport "fix gBS->Stall()" series)

* Mon Jan 19 2015 Miroslav Rezanina <mrezanin@redhat.com> - AAVMF-20141113-3.git77d5dac.el7
- aavmf-OvmfPkg-QemuBootOrderLib-expose-QEMU-s-boot-menu-on-.patch [bz#1172756]
- aavmf-OvmfPkg-PlatformBdsLib-get-front-page-timeout-from-Q.patch [bz#1172756]
- aavmf-ArmVirtualizationPkg-PlatformIntelBdsLib-get-front-p.patch [bz#1172756]
- Resolves: bz#1172756
  ([RFE]Expose boot-menu shortcut to domain via AAVMF)

* Wed Jan 14 2015 Miroslav Rezanina <mrezanin@redhat.com> - AAVMF-20141113-2.git77d5dac.el7
- aavmf-ArmVirtualizationPkg-VirtFdtDxe-forward-FwCfg-addres.patch [bz#1172749]
- aavmf-ArmVirtualizationPkg-introduce-QemuFwCfgLib-instance.patch [bz#1172749]
- aavmf-ArmVirtualizationPkg-clone-PlatformIntelBdsLib-from-.patch [bz#1172749]
- aavmf-ArmVirtualizationPkg-PlatformIntelBdsLib-add-basic-p.patch [bz#1172749]
- aavmf-OvmfPkg-extract-QemuBootOrderLib.patch [bz#1172749]
- aavmf-OvmfPkg-QemuBootOrderLib-featurize-PCI-like-device-p.patch [bz#1172749]
- aavmf-OvmfPkg-introduce-VIRTIO_MMIO_TRANSPORT_GUID.patch [bz#1172749]
- aavmf-ArmVirtualizationPkg-VirtFdtDxe-use-dedicated-VIRTIO.patch [bz#1172749]
- aavmf-OvmfPkg-QemuBootOrderLib-widen-ParseUnitAddressHexLi.patch [bz#1172749]
- aavmf-OvmfPkg-QemuBootOrderLib-OFW-to-UEFI-translation-for.patch [bz#1172749]
- aavmf-ArmVirtualizationPkg-PlatformIntelBdsLib-adhere-to-Q.patch [bz#1172749]
- aavmf-ArmVirtualizationPkg-identify-new-shell-as-builtin-s.patch [bz#1172749]
- aavmf-ArmVirtualizationPkg-Intel-BDS-load-EFI-stubbed-Linu.patch [bz#1172749]
- aavmf-spec-build-AAVMF-with-the-Intel-BDS-driver-RHELSA-on.patch [bz#1172749]
- aavmf-Revert-ArmVirtualizationPkg-work-around-cache-incohe.patch [bz#1172910]
- Resolves: bz#1172749
  (implement fw_cfg, boot order handling, and -kernel booting in ArmVirtualizationQemu)
- Resolves: bz#1172910
  (revert Acadia-only workaround (commit df7bca4e) once Acadia host kernel (KVM) is fixed)

* Fri Dec 05 2014 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20140822-7.git9ece15a.el7
- ovmf-MdePkg-UefiScsiLib-do-not-encode-LUN-in-CDB-for-READ.patch [bz#1166971]
- ovmf-MdePkg-UefiScsiLib-do-not-encode-LUN-in-CDB-for-othe.patch [bz#1166971]
- Resolves: bz#1166971
  (virtio-scsi disks and cd-roms with nonzero LUN are rejected with errors)

* Tue Nov 25 2014 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20140822-6.git9ece15a.el7
- ovmf-OvmfPkg-AcpiPlatformDxe-make-dependency-on-PCI-enume.patch [bz#1166027]
- Resolves: bz#1166027
  (backport "OvmfPkg: AcpiPlatformDxe: make dependency on PCI enumeration explicit")

* Tue Nov 18 2014 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20140822-4.git9ece15a.el7
- ovmf-Add-comments-to-clarify-mPubKeyStore-buffer-MemCopy.patch [bz#1162314]
- ovmf-MdeModulePkg-SecurityPkg-Variable-Add-boundary-check.patch [bz#1162314]
- Resolves: bz#1162314
 (EMBARGOED OVMF: uefi: INTEL-TA-201410-001 && INTEL-TA-201410-002 [rhel-7.1])

* Thu Nov 13 2014 Laszlo Ersek <lersek@redhat.com> - AAVMF-20141113-1.git77d5dac
- rebased to upstream 77d5dac
  <https://bugzilla.redhat.com/show_bug.cgi?id=1162314#c1>
- patch "ArmVirtualizationPkg: FdtPL011SerialPortLib: support UEFI_APPLICATION"
  is now upstream (SVN r16219, git edb5073)

* Thu Nov 13 2014 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20140822-3.git9ece15a.el7
- ovmf-Revert-OvmfPkg-set-video-resolution-of-text-setup-to.patch [bz#1153927]
- ovmf-Try-to-read-key-strike-even-when-the-TimeOuts-value-.patch [bz#1153927]
- ovmf-OvmfPkg-BDS-remove-dead-call-to-PlatformBdsEnterFron.patch [bz#1153927]
- ovmf-OvmfPkg-BDS-drop-useless-return-statement.patch [bz#1153927]
- ovmf-OvmfPkg-BDS-don-t-overwrite-the-BDS-Front-Page-timeo.patch [bz#1153927]
- ovmf-OvmfPkg-BDS-optimize-second-argument-in-PlatformBdsE.patch [bz#1153927]
- ovmf-OvmfPkg-BDS-drop-superfluous-connect-first-boot-opti.patch [bz#1153927]
- ovmf-OvmfPkg-BDS-drop-custom-boot-timeout-revert-to-Intel.patch [bz#1153927]
- ovmf-OvmfPkg-set-video-resolution-of-text-setup-to-640x48.patch [bz#1153927]
- Resolves: bz#1153927
  (set NEXTBOOT to uefi setting failed from Windows Recovery console)

* Tue Nov 11 2014 Miroslav Rezanina <mrezanin@redhat.com> - OVMF-20140822-2.git9ece15a
- ovmf-redhat-process-rh-specific.sh-suppress-missing-files.patch [bz#1145784]
- ovmf-Revert-RH-only-OvmfPkg-QemuVideoDxe-fix-querying-of-.patch [bz#1145784]
- ovmf-Revert-RH-only-OvmfPkg-AcpiPlatformDxe-implement-QEM.patch [bz#1145784]
- ovmf-Revert-RH-only-OvmfPkg-AcpiPlatformDxe-remove-curren.patch [bz#1145784]
- ovmf-Revert-RH-only-OvmfPkg-AcpiPlatformDxe-actualize-Qem.patch [bz#1145784]
- ovmf-Revert-RH-only-OvmfPkg-resolve-OrderedCollectionLib-.patch [bz#1145784]
- ovmf-OvmfPkg-QemuVideoDxe-work-around-misreported-QXL-fra.patch [bz#1145784]
- ovmf-OvmfPkg-resolve-OrderedCollectionLib-with-base-red-b.patch [bz#1145784]
- ovmf-OvmfPkg-AcpiPlatformDxe-actualize-QemuLoader.h-comme.patch [bz#1145784]
- ovmf-OvmfPkg-AcpiPlatformDxe-remove-current-ACPI-table-lo.patch [bz#1145784]
- ovmf-OvmfPkg-AcpiPlatformDxe-implement-QEMU-s-full-ACPI-t.patch [bz#1145784]
- ovmf-spec-build-small-bootable-ISO-with-standalone-UEFI-s.patch [bz#1147592]
- ovmf-OvmfPkg-allow-exclusion-of-the-shell-from-the-firmwa.patch [bz#1147592]
- ovmf-spec-exclude-the-UEFI-shell-from-the-SecureBoot-enab.patch [bz#1147592]
- ovmf-OvmfPkg-EnrollDefaultKeys-application-for-enrolling-.patch [bz#1148296]
- ovmf-spec-package-EnrollDefaultKeys.efi-on-UefiShell.iso-.patch [bz#1148296]
- ovmf-OvmfPkg-disable-stale-fork-of-SecureBootConfigDxe.patch [bz#1148294]
- ovmf-OvmfPkg-SecureBootConfigDxe-remove-stale-fork.patch [bz#1148294]
- Resolves: bz#1145784
  (OVMF sync with QXL and ACPI patches up to edk2 7a9612ce)
- Resolves: bz#1147592
  (the binary RPM should include a small ISO file with a directly bootable UEFI shell binary)
- Resolves: bz#1148294
  (drop OvmfPkg's stale fork of SecureBootConfigDxe)
- Resolves: bz#1148296
  (provide a non-interactive way to auto-enroll important SecureBoot certificates)

* Wed Oct 15 2014 Laszlo Ersek <lersek@redhat.com> - AAVMF-20141015-1.gitc373687
- ported packaging to aarch64 / AAVMF

* Fri Aug 22 2014 Laszlo Ersek <lersek@redhat.com> - 20140822-1.git9ece15a.el7
- rebase from upstream 3facc08 to 9ece15a
- update to openssl-0.9.8zb
- update to FatPkg SVN r86 (git 2355ea2c)
- the following patches of Paolo Bonzini have been merged in upstream; drop the
  downstream-only copies:
  7bc1421 edksetup.sh: Look for BuildEnv under EDK_TOOLS_PATH
  d549344 edksetup.sh: Ensure that WORKSPACE points to the top of an edk2
          checkout
  1c023eb BuildEnv: remove useless check before setting $WORKSPACE
- include the following patches that have been pending review on the upstream
  list for a long time:
  [PATCH 0/4] OvmfPkg: complete client for QEMU's ACPI loader interface
  http://thread.gmane.org/gmane.comp.bios.tianocore.devel/8369
  [PATCH] OvmfPkg: QemuVideoDxe: fix querying of QXL's drawable buffer size
  http://thread.gmane.org/gmane.comp.bios.tianocore.devel/8515
- nasm is a build-time dependency now because upstream BuildTools has started
  to call it directly

* Wed Jul 23 2014 Laszlo Ersek <lersek@redhat.com> - 20140723-1.git3facc08.el7
- rebase from upstream a618eaa to 3facc08
- update to openssl-0.9.8za
- drop downstream-only split varstore patch, rely on upstream's

* Tue Jun 24 2014 Miroslav Rezanina <mrezanin@redhat.com> - 20140619-1.gita618eaa.el7
- Initial version

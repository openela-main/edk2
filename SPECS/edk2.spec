ExclusiveArch: x86_64 aarch64 riscv64

# edk2-stable202511
%define GITDATE        20251114
%define GITCOMMIT      46548b1adac8
%define TOOLCHAIN      GCC

%define OPENSSL_VER    3.5.5
%define OPENSSL_HASH   c6600b817708cb4f3c6b044f28e10e9b1a1b3e2c

%define DBXDATE        20251016

%define build_ovmf 0
%define build_aarch64 0
%define build_riscv64 0
%ifarch x86_64
  %define build_ovmf 1
%endif
%ifarch aarch64
  %define build_aarch64 1
%endif
%ifarch riscv64
  %define build_riscv64 1
%endif

Name:       edk2
Version:    %{GITDATE}
Release:    5%{?dist}
Summary:    UEFI firmware for 64-bit virtual machines
License:    BSD-2-Clause-Patent and Apache-2.0 and MIT
URL:        http://www.tianocore.org

# The source tarball is created using following commands:
# COMMIT=ba91d0292e
# git archive --format=tar --prefix=edk2-$COMMIT/ $COMMIT \
# | xz -9ev >/tmp/edk2-$COMMIT.tar.xz
Source0: edk2-%{GITCOMMIT}.tar.xz
Source1: ovmf-whitepaper-c770f8c.txt
Source2: openssl-rhel-%{OPENSSL_HASH}.tar.xz
Source3: dtc-1.7.0.tar.xz

# json description files
Source10: 50-edk2-aarch64-qcow2.json
Source11: 51-edk2-aarch64-raw.json
Source12: 52-edk2-aarch64-verbose-qcow2.json
Source13: 53-edk2-aarch64-verbose-raw.json

Source20: 90-edk2-ovmf-qemuvars-x64-sb-enrolled.json
Source21: 91-edk2-ovmf-qemuvars-x64-sb.json
Source22: 90-edk2-aarch64-qemuvars-sb-enrolled.json
Source23: 91-edk2-aarch64-qemuvars-sb.json

Source40: 30-edk2-ovmf-x64-sb-enrolled.json
Source41: 40-edk2-ovmf-x64-sb.json
Source43: 50-edk2-ovmf-x64-nosb.json
Source44: 60-edk2-ovmf-x64-amdsev.json
Source45: 60-edk2-ovmf-x64-inteltdx.json

Source50: 50-edk2-riscv-qcow2.json

# https://gitlab.com/kraxel/edk2-build-config
Source80: edk2-build.py
Source82: edk2-build.rhel-10

Source90: DBXUpdate-%{DBXDATE}.x64.bin
Source91: DBXUpdate-%{DBXDATE}.aa64.bin
Patch1: 0003-Remove-paths-leading-to-submodules.patch
Patch2: 0004-MdeModulePkg-TerminalDxe-set-xterm-resolution-on-mod.patch
Patch3: 0005-OvmfPkg-take-PcdResizeXterm-from-the-QEMU-command-li.patch
Patch4: 0006-ArmVirtPkg-take-PcdResizeXterm-from-the-QEMU-command.patch
Patch5: 0007-OvmfPkg-enable-DEBUG_VERBOSE-RHEL-only.patch
Patch6: 0008-OvmfPkg-silence-DEBUG_VERBOSE-0x00400000-in-QemuVide.patch
Patch7: 0009-ArmVirtPkg-silence-DEBUG_VERBOSE-0x00400000-in-QemuR.patch
Patch8: 0010-OvmfPkg-QemuRamfbDxe-Do-not-report-DXE-failure-on-Aa.patch
Patch9: 0011-OvmfPkg-silence-EFI_D_VERBOSE-0x00400000-in-NvmExpre.patch
Patch10: 0012-OvmfPkg-QemuKernelLoaderFsDxe-suppress-error-on-no-k.patch
Patch11: 0013-SecurityPkg-Tcg2Dxe-suppress-error-on-no-swtpm-in-si.patch
Patch12: 0014-OvmfPkg-Remove-EbcDxe-RHEL-only.patch
Patch13: 0015-OvmfPkg-Remove-VirtioGpu-device-driver-RHEL-only.patch
Patch14: 0016-OvmfPkg-Remove-VirtioFsDxe-filesystem-driver-RHEL-on.patch
Patch15: 0017-ArmVirtPkg-Remove-VirtioFsDxe-filesystem-driver-RHEL.patch
Patch16: 0018-OvmfPkg-Remove-UdfDxe-filesystem-driver-RHEL-only.patch
Patch17: 0019-ArmVirtPkg-Remove-UdfDxe-filesystem-driver-RHEL-only.patch
Patch18: 0020-OvmfPkg-Remove-TftpDynamicCommand-from-shell-RHEL-on.patch
Patch19: 0021-OvmfPkg-Remove-HttpDynamicCommand-from-shell-RHEL-on.patch
Patch20: 0022-OvmfPkg-Remove-LinuxInitrdDynamicShellCommand-RHEL-o.patch
Patch21: 0023-OvmfPkg-AmdSevDxe-Shim-Reboot-workaround-RHEL-only.patch
Patch22: 0024-CryptoPkg-CrtLib-add-stat.h-include-file-RH-only.patch
Patch23: 0025-CryptoPkg-CrtLib-add-access-open-read-write-close-sy.patch
Patch24: 0026-NetworkPkg-DxeNetLib-Reword-PseudoRandom-error-loggi.patch
Patch25: 0027-OvmfPkg-Add-a-Fallback-RNG-RH-only.patch
Patch26: 0028-OvmfPkg-ArmVirtPkg-Add-a-Fallback-RNG-RH-only.patch
Patch27: 0029-OvmfPkg-X64-add-opt-org.tianocore-UninstallMemAttrPr.patch
Patch28: 0030-OvmfPkg-MemDebugLogLib-use-AcquireSpinLockOrFail.patch
Patch29: 0031-OvmfPkg-PlatformInitLib-reserve-igvm-parameter-area.patch
# For RHEL-138335 - [AmpereoneX] ArmConfigureMmu: The MaxAddress 0xFFFFFFFFFFFFF is not supported by this MMU configuration
Patch30: edk2-ArmPkg-UefiCpuPkg-Fix-boot-failure-on-FEAT_LPA-only-.patch
# For RHEL-139470 - Enable memory debug logging support in firmware image configs
Patch31: edk2-OvmfPkg-AmdSev-add-memory-debug-log-support.patch
# For RHEL-139470 - Enable memory debug logging support in firmware image configs
Patch32: edk2-OvmfPkg-MemDebugLogPeiLib-drop-duplicate-MemDebugLog.patch
# For RHEL-139470 - Enable memory debug logging support in firmware image configs
Patch33: edk2-OvmfPkg-MemDebugLogPeiCoreLib-enable-for-PEIMs.patch
# For RHEL-139470 - Enable memory debug logging support in firmware image configs
Patch34: edk2-ArmVirtPkg-use-MemDebugLogPeiCoreLib-for-PEIMs.patch
# For RHEL-139470 - Enable memory debug logging support in firmware image configs
Patch35: edk2-OvmfPkg-use-MemDebugLogPeiCoreLib-for-PEIMs.patch
# For RHEL-134956 - CVE-2025-2296 edk2: EDK2: Improper Input Validation allows arbitrary command execution [rhel-10.2]
Patch36: edk2-OvmfPkg-X86QemuLoadImageLib-flip-default-for-EnableL.patch

# python3-devel and libuuid-devel are required for building tools.
# python3-devel is also needed for varstore template generation and
# verification with "ovmf-vars-generator".
BuildRequires:  python3-devel
BuildRequires:  libuuid-devel
BuildRequires:  /usr/bin/iasl
BuildRequires:  binutils gcc git gcc-c++ make
BuildRequires:  perl perl(JSON)
BuildRequires:  qemu-img

# secure boot enrollment
BuildRequires:  python3dist(virt-firmware) >= 25.4

%if %{build_ovmf}
# Only OVMF includes 80x86 assembly files (*.nasm*).
BuildRequires:  nasm

# Only OVMF includes the Secure Boot feature, for which we need to separate out
# the UEFI shell.
BuildRequires:  dosfstools
BuildRequires:  mtools
BuildRequires:  xorriso

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
License:    BSD-2-Clause-Patent and Apache-2.0

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
License:    BSD-2-Clause-Patent and Apache-2.0

# URL taken from the Maintainers.txt file.
URL:        https://github.com/tianocore/tianocore.github.io/wiki/ArmVirtPkg

%description aarch64
AAVMF (ARM Architecture Virtual Machine Firmware) is an EFI Development Kit II
platform that enables UEFI support for QEMU/KVM ARM Virtual Machines. This
package contains a 64-bit build.


%package riscv64
Summary:    UEFI firmware for riscv64 virtual machines
BuildArch:  noarch

# No Secure Boot for riscv64 yet, but we include OpenSSL for the IPv6 stack.
Provides:   bundled(openssl) = %{OPENSSL_VER}
License:    BSD-2-Clause-Patent and Apache-2.0

%description riscv64
EFI Development Kit II platform that enables UEFI support for QEMU/KVM
RISC-V Virtual Machines. This package contains a 64-bit build.


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
cp -a -- %{SOURCE20} %{SOURCE21} %{SOURCE22} %{SOURCE23} .
cp -a -- %{SOURCE40} %{SOURCE41} %{SOURCE43} %{SOURCE44} %{SOURCE45} .
cp -a -- %{SOURCE50} .
cp -a -- %{SOURCE80} %{SOURCE82} .
cp -a -- %{SOURCE90} %{SOURCE91} .
tar -C CryptoPkg/Library/OpensslLib -a -f %{SOURCE2} -x
tar -xf %{SOURCE3} --strip-components=1 --directory MdePkg/Library/BaseFdtLib/libfdt

# Done by setup macro, but we do not use it for the auxiliary tarballs
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
python3 CryptoPkg/Library/OpensslLib/configure.py

# include dirs of unused submodules
mkdir -p CryptoPkg/Library/MbedTlsLib/mbedtls/include
mkdir -p CryptoPkg/Library/MbedTlsLib/mbedtls/include/mbedtls
mkdir -p CryptoPkg/Library/MbedTlsLib/mbedtls/library
mkdir -p SecurityPkg/DeviceSecurity/SpdmLib/libspdm/include

%if %{build_ovmf}
./edk2-build.py --config edk2-build.rhel-10 -m ovmf --release-date "$RELEASE_DATE"
build_iso RHEL-10/ovmf
cp DBXUpdate-%{DBXDATE}.x64.bin RHEL-10/ovmf
virt-fw-vars --input   RHEL-10/ovmf/OVMF_VARS.fd \
             --output  RHEL-10/ovmf/OVMF_VARS.secboot.fd \
             --set-dbx DBXUpdate-%{DBXDATE}.x64.bin \
             --enroll-redhat --secure-boot
virt-fw-vars --input   RHEL-10/ovmf/OVMF.inteltdx.fd \
             --output  RHEL-10/ovmf/OVMF.inteltdx.secboot.fd \
             --set-dbx DBXUpdate-%{DBXDATE}.x64.bin \
             --enroll-redhat --secure-boot \
             --set-fallback-no-reboot
virt-fw-vars --output-json RHEL-10/ovmf/vars.blank.json
virt-fw-vars --output-json RHEL-10/ovmf/vars.secboot.json \
             --set-dbx DBXUpdate-%{DBXDATE}.x64.bin \
             --enroll-redhat --secure-boot
%endif

%if %{build_aarch64}
./edk2-build.py --config edk2-build.rhel-10 -m armvirt --release-date "$RELEASE_DATE"
cp DBXUpdate-%{DBXDATE}.aa64.bin RHEL-10/aarch64
for raw in */aarch64/*.raw; do
    qcow2="${raw%.raw}.qcow2"
    qemu-img convert -f raw -O qcow2 -o cluster_size=4096 -S 4096 "$raw" "$qcow2"
done
virt-fw-vars --output-json RHEL-10/aarch64/vars.blank.json
virt-fw-vars --output-json RHEL-10/aarch64/vars.secboot.json \
             --set-dbx DBXUpdate-%{DBXDATE}.aa64.bin \
             --enroll-redhat --secure-boot
%endif

%if %{build_riscv64}
./edk2-build.py --config edk2-build.rhel-10 -m riscv --release-date "$RELEASE_DATE"
for raw in */riscv/*.raw; do
    qcow2="${raw%.raw}.qcow2"
    qemu-img convert -f raw -O qcow2 -o cluster_size=4096 -S 4096 "$raw" "$qcow2"
    rm -f "$raw"
done
%endif

%install

cp -a OvmfPkg/License.txt License.OvmfPkg.txt
cp -a CryptoPkg/Library/OpensslLib/openssl/LICENSE.txt LICENSE.openssl
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
cp -av RHEL-10/* %{buildroot}%{_datadir}/%{name}

%if %{build_ovmf}
mkdir -p %{buildroot}%{_datadir}/OVMF

ln -s ../%{name}/ovmf/OVMF_CODE.secboot.fd %{buildroot}%{_datadir}/OVMF/
ln -s ../%{name}/ovmf/OVMF_VARS.fd         %{buildroot}%{_datadir}/OVMF/
ln -s ../%{name}/ovmf/OVMF_VARS.secboot.fd %{buildroot}%{_datadir}/OVMF/
ln -s ../%{name}/ovmf/UefiShell.iso        %{buildroot}%{_datadir}/OVMF/
ln -s OVMF_CODE.fd %{buildroot}%{_datadir}/%{name}/ovmf/OVMF_CODE.cc.fd

install -m 0644 \
        30-edk2-ovmf-x64-sb-enrolled.json \
        90-edk2-ovmf-qemuvars-x64-sb-enrolled.json \
        40-edk2-ovmf-x64-sb.json \
        91-edk2-ovmf-qemuvars-x64-sb.json \
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
        90-edk2-aarch64-qemuvars-sb-enrolled.json \
        91-edk2-aarch64-qemuvars-sb.json \
        %{buildroot}%{_datadir}/qemu/firmware

# endif build_aarch64
%endif

%if %{build_riscv64}
install -m 0644 \
        50-edk2-riscv-qcow2.json \
        %{buildroot}%{_datadir}/qemu/firmware
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
%{_datadir}/%{name}/ovmf/OVMF.inteltdx.secboot.fd
%{_datadir}/%{name}/ovmf/OVMF.qemuvars.fd
%{_datadir}/%{name}/ovmf/DBXUpdate*.bin
%{_datadir}/%{name}/ovmf/UefiShell.iso
%{_datadir}/OVMF/OVMF_CODE.secboot.fd
%{_datadir}/OVMF/OVMF_VARS.fd
%{_datadir}/OVMF/OVMF_VARS.secboot.fd
%{_datadir}/OVMF/UefiShell.iso
%{_datadir}/%{name}/ovmf/Shell.efi
%{_datadir}/%{name}/ovmf/EnrollDefaultKeys.efi
%{_datadir}/%{name}/ovmf/vars.*.json
%{_datadir}/qemu/firmware/30-edk2-ovmf-x64-sb-enrolled.json
%{_datadir}/qemu/firmware/90-edk2-ovmf-qemuvars-x64-sb-enrolled.json
%{_datadir}/qemu/firmware/40-edk2-ovmf-x64-sb.json
%{_datadir}/qemu/firmware/91-edk2-ovmf-qemuvars-x64-sb.json
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
%{_datadir}/%{name}/aarch64/QEMU_EFI-qemuvars-pflash.*
%{_datadir}/%{name}/aarch64/vars-template-pflash.*
%{_datadir}/%{name}/aarch64/DBXUpdate*.bin
%{_datadir}/AAVMF/AAVMF_CODE.verbose.fd
%{_datadir}/AAVMF/AAVMF_CODE.fd
%{_datadir}/AAVMF/AAVMF_VARS.fd
%{_datadir}/%{name}/aarch64/QEMU_EFI.fd
%{_datadir}/%{name}/aarch64/QEMU_EFI.silent.fd
%{_datadir}/%{name}/aarch64/QEMU_EFI.qemuvars.fd
%{_datadir}/%{name}/aarch64/QEMU_VARS.fd
%{_datadir}/%{name}/aarch64/vars.*.json
%{_datadir}/qemu/firmware/50-edk2-aarch64-qcow2.json
%{_datadir}/qemu/firmware/51-edk2-aarch64-raw.json
%{_datadir}/qemu/firmware/52-edk2-aarch64-verbose-qcow2.json
%{_datadir}/qemu/firmware/53-edk2-aarch64-verbose-raw.json
%{_datadir}/qemu/firmware/90-edk2-aarch64-qemuvars-sb-enrolled.json
%{_datadir}/qemu/firmware/91-edk2-aarch64-qemuvars-sb.json
# endif build_aarch64
%endif

%if %{build_riscv64}
%files riscv64
%common_files
%{_datadir}/%{name}/riscv/*.fd
%{_datadir}/%{name}/riscv/*.qcow2
%{_datadir}/qemu/firmware/50-edk2-riscv-qcow2.json
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
* Mon Mar 09 2026 Miroslav Rezanina <mrezanin@redhat.com> - 20251114-5
- edk2-add-uefi-vars-firmware-json-files.patch [RHEL-150696]
- Resolves: RHEL-150696
  (edk2: Add JSON descriptors for uefi-vars builds)

* Thu Feb 12 2026 Miroslav Rezanina <mrezanin@redhat.com> - 20251114-4
- edk2-OvmfPkg-X86QemuLoadImageLib-flip-default-for-EnableL.patch [RHEL-134956]
- edk2-update-openssl-rhel-submodule.patch [RHEL-147785]
- edk2-update-openssl-rhel-tarball.patch [RHEL-147785]
- Resolves: RHEL-134956
  (CVE-2025-2296 edk2: EDK2: Improper Input Validation allows arbitrary command execution [rhel-10.2])
- Resolves: RHEL-147785
  ([edk2] pick up openssl updates)

* Mon Feb 09 2026 Miroslav Rezanina <mrezanin@redhat.com> - 20251114-3
- edk2-OvmfPkg-AmdSev-add-memory-debug-log-support.patch [RHEL-139470]
- edk2-OvmfPkg-MemDebugLogPeiLib-drop-duplicate-MemDebugLog.patch [RHEL-139470]
- edk2-OvmfPkg-MemDebugLogPeiCoreLib-enable-for-PEIMs.patch [RHEL-139470]
- edk2-ArmVirtPkg-use-MemDebugLogPeiCoreLib-for-PEIMs.patch [RHEL-139470]
- edk2-OvmfPkg-use-MemDebugLogPeiCoreLib-for-PEIMs.patch [RHEL-139470]
- Resolves: RHEL-139470
  (Enable memory debug logging support in firmware image configs)

* Thu Jan 08 2026 Miroslav Rezanina <mrezanin@redhat.com> - 20251114-2
- edk2-ArmPkg-UefiCpuPkg-Fix-boot-failure-on-FEAT_LPA-only-.patch [RHEL-138335]
- Resolves: RHEL-138335
  ([AmpereoneX] ArmConfigureMmu: The MaxAddress 0xFFFFFFFFFFFFF is not supported by this MMU configuration)

* Wed Dec 10 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20251114-1
- Rebase to edk2-stable202511 [RHEL-118386]
- Resolves: RHEL-118386
  ([edk2,rhel-10] rebase to edk2-stable202511)

* Wed Nov 12 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250822-4
- edk2-make-dbxupdate.sh-get-version-tag-add-to-commit-mess.patch [RHEL-126085]
- edk2-update-dbx-to-20251016-v1.6.1.patch [RHEL-126085]
- Resolves: RHEL-126085
  ([edk2,rhel-10] dbx update to 20251016 / v1.6.1)

* Mon Nov 03 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250822-3
- edk2-Bumped-OpenSSL-to-3.5.1-6.patch [RHEL-115880]
- Resolves: RHEL-115880
  (CVE-2025-9230 edk2: Out-of-bounds read & write in RFC 3211 KEK Unwrap [rhel-10.2])

* Mon Oct 13 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250822-2
- edk2-add-DBXUpdate-20250610.aa64.bin.patch [RHEL-109548]
- Resolves: RHEL-109548
  ([aarch64][edk2] missing DBXUpdate-${date}.aa64.bin)

* Tue Oct 07 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250822-1
- Rebase to edk2-stable202508 [RHEL-111718]
- Resolves: RHEL-111718
  ([edk2,rhel-10] rebase to edk2-stable202508)

* Mon Jun 30 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250523-2
- edk2-add-qemu-vars-builds-to-build-config-and-file-lists.patch [RHEL-2908]
- edk2-add-dbx-update-script.patch [RHEL-96866]
- edk2-update-dbx-to-20250610.patch [RHEL-96866]
- Resolves: RHEL-2908
  ([aarch64][EDK2] UEFI writable variable service in QEMU)
- Resolves: RHEL-96866
  ([edk2,rhel-10] dbx update 20250610)

* Tue Jun 10 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250523-1
- Rebase to edk2-stable202505 [RHEL-82556]
- Resolves: RHEL-82556
  ([edk2,rhel-10] rebase to edk2-stable202505)

* Fri May 02 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250221-3
- edk2-.distro-make-sure-virt-firmware-is-new-enough.patch [RHEL-85759]
- Resolves: RHEL-85759
  (RFE: Add riscv64 build and sub-package)

* Mon Apr 07 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250221-2
- edk2-.distro-drop-setup-macro-in-specfile-comment.patch [RHEL-85759]
- edk2-.distro-switch-to-rhel-10-build-config.patch [RHEL-85759]
- edk2-.distro-add-riscv64-sub-rpm.patch [RHEL-85759]
- Resolves: RHEL-85759
  (RFE: Add riscv64 build and sub-package)

* Wed Mar 26 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20250221-1
- Rebase to edk2-stable202502 [RHEL-75592]
- Resolves: RHEL-75592
  (rebase to edk2-stable202502)
- Resulves: RHEL-82646
  (fix typo in fwcfg file name)
- Resolves: RHEL-82837
  (The newer revocation file and Server 2025 required to update it)

* Mon Jan 20 2025 Miroslav Rezanina <mrezanin@redhat.com> - 20241117-2
- edk2-Fix-amd-sev-firmware-file-for-amd-snp.patch [RHEL-72446]
- Resolves: RHEL-72446
  ( QEMU should creating new json file that will correctly describe firmware for amd-sev-snp [rhel-10])

* Mon Dec 09 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20241117-1
- Rebase to edk2-stable202411
- Resolves: RHEL-58062
  ([edk2,rhel-10] rebase to edk2-stable202411)

* Tue Nov 26 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-12
- edk2-OvmfPkg-Rerun-dispatcher-after-initializing-virtio-r.patch [RHEL-64642]
- Resolves: RHEL-64642
  ([Regression] HTTP Boot fails to work with edk2-ovmf-20231122-6.el9_4.2 and greater [rhel-10])

* Mon Nov 11 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-11
- edk2-OvmfPkg-Add-a-Fallback-RNG-RH-only.patch [RHEL-66234]
- edk2-OvmfPkg-ArmVirtPkg-Add-a-Fallback-RNG-RH-only.patch [RHEL-66234]
- Resolves: RHEL-66234
  ([Regression] HTTP Boot not working on old vCPU without virtio-rng device present [rhel-10])

* Tue Oct 29 2024 Troy Dawson <tdawson@redhat.com> - 20240524-10
- Bump release for October 2024 mass rebuild:
  Resolves: RHEL-64018

* Tue Oct 08 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-9
- edk2-OvmfPkg-VirtioGpuDxe-ignore-display-resolutions-smal.patch [RHEL-56249]
- edk2-OvmfPkg-QemuVideoDxe-ignore-display-resolutions-smal.patch [RHEL-56249]
- edk2-MdePkg-Fix-overflow-issue-in-BasePeCoffLib.patch [RHEL-60829]
- Resolves: RHEL-56249
  (507x510 display resolution should not crash the firmware [edk2,rhel-10])
- Resolves: RHEL-60829
  (CVE-2024-38796 edk2: Integer overflows in PeCoffLoaderRelocateImage [rhel-10.0])

* Fri Sep 27 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-8
- edk2-Bumped-openssl-submodule-version-to-0205b5898872.patch [RHEL-55302]
- Resolves: RHEL-55302
  (CVE-2024-6119 edk2/openssl: Possible denial of service in X.509 name checks [rhel-10.0 beta])

* Fri Sep 13 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-7
- edk2-OvmfPkg-CpuHotplugSmm-delay-SMM-exit.patch [RHEL-56154]
- Resolves: RHEL-56154
  (qemu-kvm: warning: Blocked re-entrant IO on MemoryRegion: acpi-cpu-hotplug at addr: 0x0 [rhel-10])

* Mon Sep 09 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-5
- edk2-UefiCpuPkg-PiSmmCpuDxeSmm-skip-PatchInstructionX86-c.patch [RHEL-50185]
- Resolves: RHEL-50185
  ([RHEL10] Hit soft lockup when hotplug vcpu)

* Mon Sep 02 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-4
- edk2-AmdSevDxe-Fix-the-shim-fallback-reboot-workaround-fo.patch [RHEL-56082]
- Resolves: RHEL-56082
  ([EDK2] Shim fallback reboot workaround might not work on SNP [rhel-10])

* Tue Aug 20 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-3
- edk2-NetworkPkg-DxeNetLib-adjust-PseudoRandom-error-loggi.patch [RHEL-45829]
- edk2-NetworkPkg-DxeNetLib-Reword-PseudoRandom-error-loggi.patch [RHEL-45829]
- Resolves: RHEL-45829
  ([RHEL-10.0] edk2 hit Failed to generate random data )

* Wed Jul 24 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-2
- edk2-MdeModulePkg-Warn-if-out-of-flash-space-when-writing.patch [RHEL-45261]
- Resolves: RHEL-45261
  ([RHEL10] edk2 disconnects abnormally before loading the kernel)

* Fri Jun 28 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240524-1
- Rebase to edk2-stable202405
- Resolves: RHEL-32487

* Mon Jun 24 2024 Troy Dawson <tdawson@redhat.com> - 20240214-2
- Bump release for June 2024 mass rebuild

* Tue Apr 02 2024 Miroslav Rezanina <mrezanin@redhat.com> - 20240214-1
- Imported edk2-202402 from RHEL 9
- Resolves: RHEL-30180


import os
import re
import subprocess
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

# https://github.com/rust-lang/rust-bindgen
bindgen_cmd = 'bindgen --use-core --no-doc-comments --rust-target=1.64 '\
        '--translate-enum-integer-types --no-layout-tests '\
        '--no-prepend-enum-name --blocklist-type pt_regs'.split()

stub_skel = """#[inline(always)]
pub(crate) const unsafe fn %s_addr() -> u64 {
    0x%%s
}
"""
bindgen_kernel_cmd = '''bindgen %s --allowlist-type="(task_struct|tk_read_base|
seqcount_raw_spinlock_t|clocksource|seqcount_t|seqcount_latch_t|timekeeper|
kcsan_ctx|rnd_state|timespec64|bpf_spin_lock|bpf_sysctl_kern|xdp_buff|ethhdr|iphdr|tcphdr|udphdr|sk_buff|sock)"
--allowlist-var="(___GFP.*|CONFIG_.*)" --opaque-type xregs_state --opaque-type desc_struct
--opaque-type arch_lbr_state --opaque-type local_apic --opaque-type alt_instr
--opaque-type x86_msi_data --opaque-type x86_msi_addr_lo
--opaque-type kunit_try_catch --opaque-type spinlock --no-doc-comments
--use-core --with-derive-default --ctypes-prefix core::ffi --no-layout-tests
--no-debug '.*' --rust-target=1.64 -o %s --
-nostdinc -I$LINUX/arch/x86/include -I$LINUX/arch/x86/include/generated
-I$LINUX/include -I$LINUX/arch/x86/include/uapi
-I$LINUX/arch/x86/include/generated/uapi -I$LINUX/include/uapi
-I$LINUX/include/generated/uapi
-include $LINUX/include/linux/compiler-version.h
-include $LINUX/include/linux/kconfig.h
-include $LINUX/include/linux/compiler_types.h -D__KERNEL__
-Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs
-fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE
-Werror=implicit-function-declaration -Werror=implicit-int
-Werror=return-type -Wno-format-security -funsigned-char -std=gnu11
--target=x86_64-linux-gnu -fintegrated-as -Werror=unknown-warning-option
-Werror=ignored-optimization-argument -Werror=option-ignored
-Werror=unused-command-line-argument -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
-mno-avx -fcf-protection=none -m64 -falign-loops=1 -mno-80387
-mno-fp-ret-in-387 -mstack-alignment=8 -mskip-rax-setup -mtune=generic
-mno-red-zone -mcmodel=kernel -Wno-sign-compare -fno-asynchronous-unwind-tables
-mretpoline-external-thunk -mfunction-return=thunk-extern
-fno-delete-null-pointer-checks -Wno-frame-address
-Wno-address-of-packed-member -O2 -Wframe-larger-than=2048
-fstack-protector-strong -Wno-gnu -Wno-unused-but-set-variable
-Wno-unused-const-variable -fomit-frame-pointer -fno-stack-clash-protection
-fno-lto -falign-functions=16 -Wdeclaration-after-statement -Wvla
-Wno-pointer-sign -Wcast-function-type -Wimplicit-fallthrough
-fno-strict-overflow -fno-stack-check -Werror=date-time
-Werror=incompatible-pointer-types -Wno-initializer-overrides -Wno-format
-Wformat-extra-args -Wformat-invalid-specifier -Wformat-zero-length -Wnonnull
-Wformat-insufficient-args -Wno-sign-compare -Wno-pointer-to-enum-cast
-Wno-tautological-constant-out-of-range-compare -Wno-unaligned-access -g
-DKBUILD_MODNAME='"inner_unikernel"'
-D__BINDGEN__ -DMODULE'''

def gen_inc_directive(header):
    return '#include <%s>\n' % header

# Generates Rust binding from C/C++ header
def bindgen(header):
    p = subprocess.run([*bindgen_cmd, header], check=True, capture_output=True)
    output = p.stdout.decode('utf-8')
    assert 'std::' not in output # sanity check
    return output

def prep_headers(usr_include, headers, out_dir):
    for h in headers:
        output = bindgen(os.path.join(usr_include, h))

        subdir, file = os.path.split(h)
        subdir = os.path.join(out_dir, subdir)
        if not os.path.exists(subdir):
            os.makedirs(subdir)

        with open(os.path.join(subdir, '%s.rs' % file[:-2]), 'w') as bind_f:
            bind_f.write(output)

def parse_cargo_toml(cargo_toml_path):
    with open(cargo_toml_path, 'rb') as toml_f:
        cargo_toml = tomllib.load(toml_f)

    assert 'inner_unikernel' in cargo_toml, "no inner_unikernel config found"

    uheaders = cargo_toml['inner_unikernel'].get('uheaders', [])
    kheaders = cargo_toml['inner_unikernel'].get('kheaders', [])
    kconfigs = cargo_toml['inner_unikernel'].get('kconfigs', [])

    return uheaders, kheaders, kconfigs

def prep_kernel_headers(headers, linux_path, out_dir):
    bindings_h = os.path.join(out_dir, 'bindings.h')
    out_subdir = os.path.join(out_dir, 'linux')
    if not os.path.exists(out_subdir):
        os.makedirs(out_subdir)
    kernel_rs = os.path.join(out_subdir, 'kernel.rs')

    with open(bindings_h, 'w') as bindings:
        for h in headers:
            bindings.write(gen_inc_directive(h))

    cmd = bindgen_kernel_cmd.replace('\n', ' ').replace('$LINUX', linux_path)
    subprocess.run(cmd % (bindings_h, kernel_rs), check=True, shell=True)

def parse_kconfigs(dot_config_path, kconfigs):
    if len(kconfigs) == 0:
        return

    with open(dot_config_path) as dot_config:
        dot_config_content = dot_config.readlines()

    ptn = re.compile('(%s)' % '|'.join(kconfigs))

    print('\n'.join(map(lambda l: 'cargo:rustc-cfg=%s="%s"' % l,
                        map(lambda l: tuple(l.strip().split('=')),
                            filter(lambda l: l[0] != '#' and ptn.match(l),
                                   dot_config_content)))))

def main(argv):
    linux_path = argv[1]
    out_dir = argv[2]
    target_path = os.getcwd()

    result = parse_cargo_toml(os.path.join(target_path, 'Cargo.toml'))
    uheaders, kheaders, kconfigs = result

    u_out_dir = os.path.join(out_dir, 'uapi')
    prep_headers(os.path.join(linux_path, 'usr/include'), uheaders, u_out_dir)
    prep_kernel_headers(kheaders, linux_path, out_dir)
    parse_kconfigs(os.path.join(linux_path, '.config'), kconfigs)
    return 0

if __name__ == '__main__':
    exit(main(sys.argv))

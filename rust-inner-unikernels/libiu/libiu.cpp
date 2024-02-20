#define _DEFAULT_SOURCE

#include <bpf/libbpf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "libiu.h"
#include "list.h"

#ifdef ARRAY_SIZE
// Kernel ARRAY_SIZE generates compiler errors
#undef ARRAY_SIZE
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define BPF_INSN_SZ (sizeof(struct bpf_insn))

// https://elixir.bootlin.com/linux/v5.15/source/tools/lib/bpf/libbpf.c
#ifndef zfree
#define zfree(ptr)                                                             \
  ({                                                                           \
    free(*ptr);                                                                \
    *ptr = NULL;                                                               \
  })
#endif

// https://elixir.bootlin.com/linux/v5.15/source/tools/lib/bpf/libbpf.c#L224
struct bpf_sec_def;

typedef struct bpf_link *(*attach_fn_t)(const struct bpf_sec_def *sec,
                                        struct bpf_program *prog);

struct bpf_sec_def {
  const char *sec;
  size_t len;
  enum bpf_prog_type prog_type;
  enum bpf_attach_type expected_attach_type;
  bool is_exp_attach_type_optional;
  bool is_attachable;
  bool is_attach_btf;
  bool is_sleepable;
  attach_fn_t attach_fn;
};

#define BPF_PROG_SEC_IMPL(string, ptype, eatype, eatype_optional, attachable,  \
                          attach_btf)                                          \
  {                                                                            \
    .sec = string, .len = sizeof(string) - 1, .prog_type = ptype,              \
    .expected_attach_type = (enum bpf_attach_type)eatype,                      \
    .is_exp_attach_type_optional = eatype_optional,                            \
    .is_attachable = attachable, .is_attach_btf = attach_btf,                  \
  }

/* Programs that can NOT be attached. */
#define BPF_PROG_SEC(string, ptype) BPF_PROG_SEC_IMPL(string, ptype, 0, 0, 0, 0)

/* Programs that can be attached. */
#define BPF_APROG_SEC(string, ptype, atype)                                    \
  BPF_PROG_SEC_IMPL(string, ptype, atype, true, 1, 0)

/* Programs that must specify expected attach type at load time. */
#define BPF_EAPROG_SEC(string, ptype, eatype)                                  \
  BPF_PROG_SEC_IMPL(string, ptype, eatype, false, 1, 0)

/* Programs that use BTF to identify attach point */
#define BPF_PROG_BTF(string, ptype, eatype)                                    \
  BPF_PROG_SEC_IMPL(string, ptype, eatype, false, 0, 1)

/* Programs that can be attached but attach type can't be identified by section
 * name. Kept for backward compatibility.
 */
#define BPF_APROG_COMPAT(string, ptype) BPF_PROG_SEC(string, ptype)

#define SEC_DEF(sec_pfx, ptype, ...)                                           \
  {                                                                            \
    .sec = sec_pfx, .len = sizeof(sec_pfx) - 1,                                \
    .prog_type = BPF_PROG_TYPE_##ptype, __VA_ARGS__                            \
  }

extern "C" {
extern struct bpf_link *attach_kprobe(const struct bpf_sec_def *sec,
                                      struct bpf_program *prog);
extern struct bpf_link *attach_tp(const struct bpf_sec_def *sec,
                                  struct bpf_program *prog);
extern struct bpf_link *attach_raw_tp(const struct bpf_sec_def *sec,
                                      struct bpf_program *prog);
extern struct bpf_link *attach_trace(const struct bpf_sec_def *sec,
                                     struct bpf_program *prog);
extern struct bpf_link *attach_lsm(const struct bpf_sec_def *sec,
                                   struct bpf_program *prog);
extern struct bpf_link *attach_iter(const struct bpf_sec_def *sec,
                                    struct bpf_program *prog);
}

static const struct bpf_sec_def section_defs[] = {
    BPF_PROG_SEC("socket", BPF_PROG_TYPE_SOCKET_FILTER),
    BPF_EAPROG_SEC("sk_reuseport/migrate", BPF_PROG_TYPE_SK_REUSEPORT,
                   BPF_SK_REUSEPORT_SELECT_OR_MIGRATE),
    BPF_EAPROG_SEC("sk_reuseport", BPF_PROG_TYPE_SK_REUSEPORT,
                   BPF_SK_REUSEPORT_SELECT),
    SEC_DEF("kprobe/", KPROBE, .attach_fn = attach_kprobe),
    BPF_PROG_SEC("uprobe/", BPF_PROG_TYPE_KPROBE),
    SEC_DEF("kretprobe/", KPROBE, .attach_fn = attach_kprobe),
    BPF_PROG_SEC("uretprobe/", BPF_PROG_TYPE_KPROBE),
    BPF_PROG_SEC("tc", BPF_PROG_TYPE_SCHED_CLS),
    BPF_PROG_SEC("classifier", BPF_PROG_TYPE_SCHED_CLS),
    BPF_PROG_SEC("action", BPF_PROG_TYPE_SCHED_ACT),
    SEC_DEF("tracepoint/", TRACEPOINT, .attach_fn = attach_tp),
    SEC_DEF("tp/", TRACEPOINT, .attach_fn = attach_tp),
    SEC_DEF("raw_tracepoint/", RAW_TRACEPOINT, .attach_fn = attach_raw_tp),
    SEC_DEF("raw_tp/", RAW_TRACEPOINT, .attach_fn = attach_raw_tp),
    SEC_DEF("tp_btf/", TRACING, .expected_attach_type = BPF_TRACE_RAW_TP,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fentry/", TRACING, .expected_attach_type = BPF_TRACE_FENTRY,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fmod_ret/", TRACING, .expected_attach_type = BPF_MODIFY_RETURN,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fexit/", TRACING, .expected_attach_type = BPF_TRACE_FEXIT,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fentry.s/", TRACING, .expected_attach_type = BPF_TRACE_FENTRY,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_trace),
    SEC_DEF("fmod_ret.s/", TRACING, .expected_attach_type = BPF_MODIFY_RETURN,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_trace),
    SEC_DEF("fexit.s/", TRACING, .expected_attach_type = BPF_TRACE_FEXIT,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_trace),
    SEC_DEF("freplace/", EXT, .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("lsm/", LSM, .expected_attach_type = BPF_LSM_MAC,
            .is_attach_btf = true, .attach_fn = attach_lsm),
    SEC_DEF("lsm.s/", LSM, .expected_attach_type = BPF_LSM_MAC,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_lsm),
    SEC_DEF("iter/", TRACING, .expected_attach_type = BPF_TRACE_ITER,
            .is_attach_btf = true, .attach_fn = attach_iter),
    SEC_DEF("syscall", SYSCALL, .is_sleepable = true),
    BPF_EAPROG_SEC("xdp_devmap/", BPF_PROG_TYPE_XDP, BPF_XDP_DEVMAP),
    BPF_EAPROG_SEC("xdp_cpumap/", BPF_PROG_TYPE_XDP, BPF_XDP_CPUMAP),
    BPF_APROG_SEC("xdp", BPF_PROG_TYPE_XDP, BPF_XDP),
    BPF_PROG_SEC("perf_event", BPF_PROG_TYPE_PERF_EVENT),
    BPF_PROG_SEC("lwt_in", BPF_PROG_TYPE_LWT_IN),
    BPF_PROG_SEC("lwt_out", BPF_PROG_TYPE_LWT_OUT),
    BPF_PROG_SEC("lwt_xmit", BPF_PROG_TYPE_LWT_XMIT),
    BPF_PROG_SEC("lwt_seg6local", BPF_PROG_TYPE_LWT_SEG6LOCAL),
    BPF_APROG_SEC("cgroup_skb/ingress", BPF_PROG_TYPE_CGROUP_SKB,
                  BPF_CGROUP_INET_INGRESS),
    BPF_APROG_SEC("cgroup_skb/egress", BPF_PROG_TYPE_CGROUP_SKB,
                  BPF_CGROUP_INET_EGRESS),
    BPF_APROG_COMPAT("cgroup/skb", BPF_PROG_TYPE_CGROUP_SKB),
    BPF_EAPROG_SEC("cgroup/sock_create", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET_SOCK_CREATE),
    BPF_EAPROG_SEC("cgroup/sock_release", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET_SOCK_RELEASE),
    BPF_APROG_SEC("cgroup/sock", BPF_PROG_TYPE_CGROUP_SOCK,
                  BPF_CGROUP_INET_SOCK_CREATE),
    BPF_EAPROG_SEC("cgroup/post_bind4", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET4_POST_BIND),
    BPF_EAPROG_SEC("cgroup/post_bind6", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET6_POST_BIND),
    BPF_APROG_SEC("cgroup/dev", BPF_PROG_TYPE_CGROUP_DEVICE, BPF_CGROUP_DEVICE),
    BPF_APROG_SEC("sockops", BPF_PROG_TYPE_SOCK_OPS, BPF_CGROUP_SOCK_OPS),
    BPF_APROG_SEC("sk_skb/stream_parser", BPF_PROG_TYPE_SK_SKB,
                  BPF_SK_SKB_STREAM_PARSER),
    BPF_APROG_SEC("sk_skb/stream_verdict", BPF_PROG_TYPE_SK_SKB,
                  BPF_SK_SKB_STREAM_VERDICT),
    BPF_APROG_COMPAT("sk_skb", BPF_PROG_TYPE_SK_SKB),
    BPF_APROG_SEC("sk_msg", BPF_PROG_TYPE_SK_MSG, BPF_SK_MSG_VERDICT),
    BPF_APROG_SEC("lirc_mode2", BPF_PROG_TYPE_LIRC_MODE2, BPF_LIRC_MODE2),
    BPF_APROG_SEC("flow_dissector", BPF_PROG_TYPE_FLOW_DISSECTOR,
                  BPF_FLOW_DISSECTOR),
    BPF_EAPROG_SEC("cgroup/bind4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_BIND),
    BPF_EAPROG_SEC("cgroup/bind6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_BIND),
    BPF_EAPROG_SEC("cgroup/connect4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_CONNECT),
    BPF_EAPROG_SEC("cgroup/connect6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_CONNECT),
    BPF_EAPROG_SEC("cgroup/sendmsg4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP4_SENDMSG),
    BPF_EAPROG_SEC("cgroup/sendmsg6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP6_SENDMSG),
    BPF_EAPROG_SEC("cgroup/recvmsg4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP4_RECVMSG),
    BPF_EAPROG_SEC("cgroup/recvmsg6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP6_RECVMSG),
    BPF_EAPROG_SEC("cgroup/getpeername4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_GETPEERNAME),
    BPF_EAPROG_SEC("cgroup/getpeername6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_GETPEERNAME),
    BPF_EAPROG_SEC("cgroup/getsockname4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_GETSOCKNAME),
    BPF_EAPROG_SEC("cgroup/getsockname6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_GETSOCKNAME),
    BPF_EAPROG_SEC("cgroup/sysctl", BPF_PROG_TYPE_CGROUP_SYSCTL,
                   BPF_CGROUP_SYSCTL),
    BPF_EAPROG_SEC("cgroup/getsockopt", BPF_PROG_TYPE_CGROUP_SOCKOPT,
                   BPF_CGROUP_GETSOCKOPT),
    BPF_EAPROG_SEC("cgroup/setsockopt", BPF_PROG_TYPE_CGROUP_SOCKOPT,
                   BPF_CGROUP_SETSOCKOPT),
    BPF_PROG_SEC("struct_ops", BPF_PROG_TYPE_STRUCT_OPS),
    BPF_EAPROG_SEC("sk_lookup/", BPF_PROG_TYPE_SK_LOOKUP, BPF_SK_LOOKUP),
};

#undef BPF_PROG_SEC_IMPL
#undef BPF_PROG_SEC
#undef BPF_APROG_SEC
#undef BPF_EAPROG_SEC
#undef BPF_APROG_COMPAT
#undef SEC_DEF

enum libbpf_map_type {
  LIBBPF_MAP_UNSPEC,
  LIBBPF_MAP_DATA,
  LIBBPF_MAP_BSS,
  LIBBPF_MAP_RODATA,
  LIBBPF_MAP_KCONFIG,
};

static LIST_HEAD(bpf_objects_list);

struct bpf_object {
  char name[BPF_OBJ_NAME_LEN];
  char license[64];
  __u32 kern_version;

  struct bpf_program *programs;
  size_t nr_programs;
  struct bpf_map *maps;
  size_t nr_maps;
  size_t maps_cap;

  char *kconfig;
  struct extern_desc *externs;
  int nr_extern;
  int kconfig_map_idx;
  int rodata_map_idx;

  bool loaded;
  bool has_subcalls;

  struct bpf_gen *gen_loader;

  struct {
    int fd;
    const void *obj_buf;
    size_t obj_buf_sz;
    Elf *elf;
    GElf_Ehdr ehdr;
    Elf_Data *symbols;
    Elf_Data *data;
    Elf_Data *rodata;
    Elf_Data *bss;
    Elf_Data *st_ops_data;
    size_t shstrndx; /* section index for section name strings */
    size_t strtabidx;
    struct {
      GElf_Shdr shdr;
      Elf_Data *data;
    } *reloc_sects;
    int nr_reloc_sects;
    int maps_shndx;
    int btf_maps_shndx;
    __u32 btf_maps_sec_btf_id;
    int text_shndx;
    int symbols_shndx;
    int data_shndx;
    int rodata_shndx;
    int bss_shndx;
    int st_ops_shndx;
  } efile;

  struct list_head list;

  struct btf *btf;
  struct btf_ext *btf_ext;

  struct btf *btf_vmlinux;
  char *btf_custom_path;
  struct btf *btf_vmlinux_override;
  struct module_btf *btf_modules;
  bool btf_modules_loaded;
  size_t btf_module_cnt;
  size_t btf_module_cap;

  void *priv;
  bpf_object_clear_priv_t clear_priv;

  char path[];
};

struct bpf_program {
  const struct bpf_sec_def *sec_def;
  char *sec_name;
  size_t sec_idx;
  size_t sec_insn_off;
  size_t sec_insn_cnt;
  size_t sub_insn_off;

  char *name;
  char *pin_name;

  struct bpf_insn *insns;
  size_t insns_cnt;

  struct reloc_desc *reloc_desc;
  int nr_reloc;
  int log_level;

  struct {
    int nr;
    int *fds;
  } instances;
  bpf_program_prep_t preprocessor;

  struct bpf_object *obj;
  void *priv;
  bpf_program_clear_priv_t clear_priv;

  bool load;
  bool mark_btf_static;
  enum bpf_prog_type type;
  enum bpf_attach_type expected_attach_type;
  int prog_ifindex;
  __u32 attach_btf_obj_fd;
  __u32 attach_btf_id;
  __u32 attach_prog_fd;
  void *func_info;
  __u32 func_info_rec_size;
  __u32 func_info_cnt;

  void *line_info;
  __u32 line_info_rec_size;
  __u32 line_info_cnt;
  __u32 prog_flags;
};

struct bpf_map {
  char *name;
  int fd;
  int sec_idx;
  size_t sec_offset;
  int map_ifindex;
  int inner_map_fd;
  struct bpf_map_def def;
  __u32 numa_node;
  __u32 btf_var_idx;
  __u32 btf_key_type_id;
  __u32 btf_value_type_id;
  __u32 btf_vmlinux_value_type_id;
  void *priv;
  bpf_map_clear_priv_t clear_priv;
  enum libbpf_map_type libbpf_type;
  void *mmaped;
  struct bpf_struct_ops *st_ops;
  struct bpf_map *inner_map;
  void **init_slots;
  int init_slots_sz;
  char *pin_path;
  bool pinned;
  bool reused;
};

namespace { // begin anynomous namespace

static const struct bpf_sec_def *find_sec_def(const char *sec_name) {
  int i, n = ARRAY_SIZE(section_defs);

  for (i = 0; i < n; i++) {
    if (strncmp(sec_name, section_defs[i].sec, section_defs[i].len))
      continue;
    return &section_defs[i];
  }
  return NULL;
}

class iu_obj; // forward declaration

static int debug = 0;
static std::unordered_map<int, std::unique_ptr<iu_obj>> objs;

static inline int64_t get_file_size(int fd) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    return -1;
  }

  return st.st_size;
}

template <typename T, std::enable_if_t<std::is_integral<T>::value, bool> = true>
static inline T val_from_buf(const unsigned char *buf) {
  return *reinterpret_cast<const T *>(buf);
}

template <typename T, std::enable_if_t<std::is_integral<T>::value, bool> = true>
static inline void val_to_buf(unsigned char *buf, const T val) {
  *reinterpret_cast<T *>(buf) = val;
}

static inline long bpf(__u64 cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

// This struct is POD, meaning the C++ standard guarantees the same memory
// layout as that of the equivalent C struct
// https://stackoverflow.com/questions/422830/structure-of-a-c-object-in-memory-vs-a-struct
struct map_def {
  uint32_t map_type;
  uint32_t key_size;
  uint32_t val_size;
  uint32_t max_size;
  uint32_t map_flag;
  void *kptr;
};

class iu_map {
  map_def def;
  int map_fd;
  const std::string name; // for debug msg

public:
  iu_map() = delete;
  iu_map(const Elf_Data *, Elf64_Addr, Elf64_Off, const char *);
  ~iu_map();

  int create();

  friend class iu_obj; // for debug msg
};

iu_map::iu_map(const Elf_Data *data, Elf64_Addr base, Elf64_Off off,
               const char *c_name)
    : map_fd(-1), name(c_name) {
  auto def_addr = reinterpret_cast<uint64_t>(data->d_buf) + off - base;
  this->def = *reinterpret_cast<map_def *>(def_addr);

  if (debug) {
    std::clog << "sym_name=" << c_name << std::endl;
    std::clog << "map_type=" << this->def.map_type << std::endl;
    std::clog << "key_size=" << this->def.key_size << std::endl;
    std::clog << "val_size=" << this->def.val_size << std::endl;
    std::clog << "max_size=" << this->def.max_size << std::endl;
    std::clog << "map_flag=" << this->def.map_flag << std::endl;
  }
}

iu_map::~iu_map() {
  if (map_fd >= 0)
    close(map_fd);
}

int iu_map::create() {
  const auto &def = this->def;

  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));

  attr.map_type = def.map_type;
  attr.key_size = def.key_size;
  attr.value_size = def.val_size;
  attr.max_entries = def.max_size;
  attr.map_flags = def.map_flag;

  if (name.size() < BPF_OBJ_NAME_LEN)
    memcpy(attr.map_name, name.c_str(), name.size());

  this->map_fd = static_cast<int>(bpf(BPF_MAP_CREATE, &attr, sizeof(attr)));
  return this->map_fd;
}

class iu_obj {
  struct iu_prog {
    std::string name;
    int prog_type;
    Elf64_Off offset;
    int fd;

    iu_prog() = delete;
    iu_prog(const char *nm, int prog_ty, Elf64_Off off)
        : name(nm), prog_type(prog_ty), offset(off), fd(-1) {}
    ~iu_prog() = default;
  };

  std::unordered_map<Elf64_Off, iu_map> map_defs;
  std::unordered_map<std::string, const iu_map *> name2map;
  std::unordered_map<std::string, iu_prog> progs;

  Elf *elf;
  Elf_Scn *symtab_scn;
  Elf_Scn *dynsym_scn;
  Elf_Scn *maps_scn;

  // Global Offset Table for PIE
  Elf_Scn *got_scn;

  // Dynamic relocation for PIE
  Elf_Scn *rela_dyn_scn;
  std::vector<iu_rela_dyn> dyn_relas;
  std::vector<iu_dyn_sym> dyn_syms;

  size_t file_size;
  unsigned char *file_map;
  int prog_fd;

  int parse_scns(struct bpf_object *);
  int parse_maps(struct bpf_object *);
  int parse_progs(struct bpf_object *);
  int parse_got();
  int parse_rela_dyn();

public:
  iu_obj() = delete;
  iu_obj(const char *, struct bpf_object *);
  iu_obj(const iu_obj &) = delete;
  iu_obj(iu_obj &&) = delete;
  ~iu_obj();

  iu_obj &operator=(const iu_obj &) = delete;
  iu_obj &operator=(iu_obj &&) = delete;

  // Making this a separate function to avoid exceptions in constructor
  int parse_elf(struct bpf_object *);

  int fix_maps(struct bpf_object *);
  int load(struct bpf_object *);
  int find_map_by_name(const char *) const;
  int find_prog_by_name(const char *) const;
};

} // namespace

static void iu_object__elf_finish(struct bpf_object *obj) {
  // if (obj->efile.elf) {
  // 	elf_end(obj->efile.elf);
  // 	obj->efile.elf = NULL;
  // }

  obj->efile.symbols = NULL;
  obj->efile.data = NULL;
  obj->efile.rodata = NULL;
  obj->efile.bss = NULL;
  obj->efile.st_ops_data = NULL;

  obj->efile.reloc_sects = NULL;
  obj->efile.nr_reloc_sects = 0;
  close(obj->efile.fd);
  obj->efile.fd = -1;
  obj->efile.obj_buf = NULL;
  obj->efile.obj_buf_sz = 0;
}

static char *__iu_program__pin_name(struct bpf_program *prog) {
  char *name, *p;

  name = p = strdup(prog->sec_name);
  while ((p = strchr(p, '/')))
    *p = '_';

  return name;
}

static void iu_program__exit(struct bpf_program *prog) {
  if (!prog)
    return;

  if (prog->clear_priv)
    prog->clear_priv(prog, prog->priv);

  prog->priv = NULL;
  prog->clear_priv = NULL;

  if (prog->instances.nr > 0) {
    for (int i = 0; i < prog->instances.nr; i++)
      close(prog->instances.fds[i]);
  }
  prog->instances.nr = -1;
  zfree(&prog->instances.fds);
  zfree(&prog->func_info);
  zfree(&prog->line_info);
  zfree(&prog->name);
  zfree(&prog->sec_name);
  zfree(&prog->pin_name);
  zfree(&prog->insns);
  zfree(&prog->reloc_desc);

  prog->nr_reloc = 0;
  prog->insns_cnt = 0;
  prog->sec_idx = -1;
}

static struct bpf_map *iu_object__add_map(struct bpf_object *obj) {
  struct bpf_map *new_maps;
  size_t new_cap;
  int i;

  if (obj->nr_maps < obj->maps_cap)
    return &obj->maps[obj->nr_maps++];

  new_cap =
      (obj->maps_cap * 3 / 2) > (size_t)4 ? obj->maps_cap * 3 / 2 : (size_t)4;
  new_maps = (struct bpf_map *)realloc(obj->maps, new_cap * sizeof(*obj->maps));
  if (!new_maps) {
    std::cerr << "alloc maps for object failed" << std::endl;
    return NULL;
  }

  obj->maps_cap = new_cap;
  obj->maps = new_maps;

  /* zero out new maps */
  memset(obj->maps + obj->nr_maps, 0,
         (obj->maps_cap - obj->nr_maps) * sizeof(*obj->maps));
  /*
   * fill all fd with -1 so won't close incorrect fd (fd=0 is stdin)
   * when failure (zclose won't close negative fd)).
   */
  for (i = obj->nr_maps; i < obj->maps_cap; i++) {
    obj->maps[i].fd = -1;
    obj->maps[i].inner_map_fd = -1;
  }

  return &obj->maps[obj->nr_maps++];
}

static int iu_object__init_prog(struct bpf_object *obj,
                                struct bpf_program *prog, const char *name,
                                size_t sec_idx, const char *sec_name,
                                size_t sec_off, void *insn_data,
                                size_t insn_data_sz,
                                const struct bpf_sec_def *sec_def) {
  memset(prog, 0, sizeof(*prog));
  prog->obj = obj;
  prog->sec_def = sec_def;
  prog->sec_idx = sec_idx;
  prog->sec_insn_off = sec_off / BPF_INSN_SZ;
  prog->sec_insn_cnt = insn_data_sz / BPF_INSN_SZ;
  /* insns_cnt can later be increased by appending used subprograms */
  prog->insns_cnt = 0;

  prog->type = sec_def->prog_type;
  prog->expected_attach_type = sec_def->expected_attach_type;
  prog->load = true;

  prog->instances.fds = NULL;
  prog->instances.nr = -1;

  prog->sec_name = strdup(sec_name);
  if (!prog->sec_name)
    goto errout;

  prog->name = strdup(name);
  if (!prog->name)
    goto errout;

  prog->pin_name = __iu_program__pin_name(prog);
  if (!prog->pin_name)
    goto errout;

  if (prog->sec_def->is_sleepable)
    prog->prog_flags |= BPF_F_SLEEPABLE;

  return 0;
errout:
  std::cerr << "failed to allocate memory for prog" << std::endl;
  iu_program__exit(prog);
  return -ENOMEM;
}

static int cmp_progs(const void *_a, const void *_b) {
  const struct bpf_program *a = (struct bpf_program *)_a;
  const struct bpf_program *b = (struct bpf_program *)_b;

  if (a->sec_idx != b->sec_idx)
    return a->sec_idx < b->sec_idx ? -1 : 1;

  /* sec_insn_off can't be the same within the section */
  return a->sec_insn_off < b->sec_insn_off ? -1 : 1;
}

iu_obj::iu_obj(const char *c_path, struct bpf_object *bpf_obj)
    : map_defs(), symtab_scn(nullptr), dynsym_scn(nullptr), maps_scn(nullptr),
      prog_fd(-1) {
  int fd = open(c_path, 0, O_RDONLY);
  bpf_obj->efile.fd = fd;
  this->elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
  bpf_obj->efile.elf = this->elf;
  file_size = get_file_size(fd);

  // MAP_PRIVATE ensures the changes are not carried through to the backing
  // file
  // reference: `man 2 mmap`
  file_map = reinterpret_cast<unsigned char *>(
      mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));
  // close(fd);
}

iu_obj::~iu_obj() {
  if (this->elf)
    elf_end(this->elf);

  if (file_map)
    munmap(file_map, file_size);

  if (prog_fd >= 0)
    close(prog_fd);
}

int iu_obj::parse_scns(struct bpf_object *obj) {
  size_t shstrndx;

  if (!gelf_getehdr(obj->efile.elf, &obj->efile.ehdr)) {
    std::cerr << "elf: failed to get ELF header from " << obj->path
              << elf_errmsg(-1) << std::endl;
    return -1;
  }

  if (elf_getshdrstrndx(obj->efile.elf, &obj->efile.shstrndx)) {
    std::cerr << "elf: failed to get section names section index for "
              << obj->path << elf_errmsg(-1) << std::endl;
    return -1;
  }
  shstrndx = obj->efile.shstrndx;

  for (auto scn = elf_nextscn(elf, NULL); scn; scn = elf_nextscn(elf, scn)) {
    char *name;
    int idx = elf_ndxscn(scn);
    Elf64_Shdr *sh = elf64_getshdr(scn);
    Elf_Data *data;
    if (!sh) {
      std::cerr << "elf: failed to get section header, idx=" << idx
                << std::endl;
      return -1;
    }

    name = elf_strptr(this->elf, shstrndx, sh->sh_name);

    if (!name) {
      std::cerr << "elf: failed to get section name" << std::endl;
      return -1;
    }

    if (debug)
      std::clog << "section " << name << ", idx=" << idx << std::endl;

    if (sh->sh_type == SHT_SYMTAB && !strcmp(".symtab", name)) {
      data = elf_getdata(scn, 0);
      if (!data) {
        std::cerr << "elf: failed to get section(" << idx << ") data from "
                  << obj->path << ": " << elf_errmsg(-1) << std::endl;
        return -1;
      }
      obj->efile.symbols = data;
      obj->efile.symbols_shndx = idx;
      obj->efile.strtabidx = sh->sh_link;
      this->symtab_scn = scn;
    } else if (sh->sh_type == SHT_DYNSYM && !strcmp(".dynsym", name)) {
      this->dynsym_scn = scn;
    } else if (!strcmp(".maps", name)) {
      obj->efile.maps_shndx = idx;
      this->maps_scn = scn;
    }
    // Except symtab and maps, other indexes are saved only for checks in some
    // libbpf functions
    else if (!(strcmp(name, ".text")))
      obj->efile.text_shndx = idx;
    else if (!(strcmp(name, ".data")))
      obj->efile.data_shndx = idx;
    else if (!(strcmp(name, ".rodata")))
      obj->efile.rodata_shndx = idx;
    else if (!(strcmp(name, ".struct_ops")))
      obj->efile.st_ops_shndx = idx;
    else if (!(strcmp(name, ".bss")))
      obj->efile.bss_shndx = idx;
    else if (sh->sh_type == SHT_RELA && !strcmp(".rela.dyn", name))
      this->rela_dyn_scn = scn;
  }

  if (!this->maps_scn && debug)
    std::clog << "section .maps not found" << std::endl;

  if (!this->rela_dyn_scn && debug)
    std::clog << "section .rela.dyn not found" << std::endl;

  return 0;
}

int iu_obj::parse_maps(struct bpf_object *obj) {
  Elf_Data *maps, *syms;
  int nr_syms, nr_maps = 0, maps_shndx;
  size_t strtabidx;
  Elf64_Addr maps_shaddr;

  if (!this->maps_scn)
    return 0;

  maps = elf_getdata(maps_scn, 0);
  syms = elf_getdata(symtab_scn, 0);

  if (!syms) {
    std::cerr << "elf: failed to get symbol definitions" << std::endl;
    return -1;
  }

  if (!maps) {
    std::cerr << "elf: failed to get map definitions" << std::endl;
    return -1;
  }

  strtabidx = elf64_getshdr(symtab_scn)->sh_link;
  maps_shndx = elf_ndxscn(maps_scn);
  maps_shaddr = elf64_getshdr(maps_scn)->sh_addr;
  nr_syms = syms->d_size / sizeof(Elf64_Sym);

  for (int i = 0; i < nr_syms; i++) {
    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + i;
    char *name;
    struct bpf_map_def *def;
    struct bpf_map *map;

    if (sym->st_shndx != maps_shndx ||
        ELF64_ST_TYPE(sym->st_info) != STT_OBJECT)
      continue;

    map = iu_object__add_map(obj);
    if (!map) {
      std::cerr << "failed to alloc map" << std::endl;
      return -ENOMEM;
    }
    name = elf_strptr(elf, strtabidx, sym->st_name);
    map->libbpf_type = LIBBPF_MAP_UNSPEC;
    map->sec_idx = sym->st_shndx;
    map->sec_offset = sym->st_value;
    map->name = strdup(name);
    if (!map->name) {
      std::cerr << "failed to alloc map name" << std::endl;
      return -ENOMEM;
    }
    def = (struct bpf_map_def *)((char *)maps->d_buf + sym->st_value);
    memcpy(&map->def, def, sizeof(struct bpf_map_def));
    if (debug) {
      std::clog << "symbol: " << name << ", st_value=0x" << std::hex
                << sym->st_value << ", st_size=" << std::dec << sym->st_size
                << std::endl;
    }

    if (sym->st_size == sizeof(struct map_def)) {
      map_defs.try_emplace(sym->st_value, maps, maps_shaddr, sym->st_value,
                           name);
    }

    nr_maps++;
  }

  if (debug)
    std::clog << "# of symbols in \".maps\": " << nr_maps << std::endl;

  return 0;
}

// get sec name
// get function symbols
int iu_obj::parse_progs(struct bpf_object *obj) {
  size_t shstrndx, strtabidx;
  Elf_Data *syms;
  int nr_syms;
  struct bpf_program *bpf_prog, *bpf_progs;
  int nr_progs;

  strtabidx = elf64_getshdr(symtab_scn)->sh_link;

  if (elf_getshdrstrndx(elf, &shstrndx)) {
    std::cerr << "elf: failed to get section names section index" << std::endl;
    return -1;
  }

  syms = elf_getdata(symtab_scn, 0);

  if (!syms) {
    std::cerr << "elf: failed to get symbol definitions" << std::endl;
    return -1;
  }
  bpf_progs = obj->programs;
  nr_progs = obj->nr_programs;
  nr_syms = syms->d_size / sizeof(Elf64_Sym);

  for (int i = 0; i < nr_syms; i++) {
    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + i;
    Elf_Scn *scn = elf_getscn(this->elf, sym->st_shndx);
    char *scn_name, *sym_name;
    Elf_Data *data;
    const struct bpf_sec_def *sec_def;

    if (!scn || ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    scn_name = elf_strptr(this->elf, shstrndx, elf64_getshdr(scn)->sh_name);
    sym_name = elf_strptr(elf, strtabidx, sym->st_name);
    /*if (debug) {
            std::clog << "section: \"" << scn_name << "\"" << std::endl;
            std::clog << "symbol: \"" << sym_name << "\"" << std::endl;
    }*/

    data = elf_getdata(scn, 0);

    sec_def = find_sec_def(scn_name);
    if (!sec_def)
      continue;
    int prog_type = sec_def->prog_type;

    sym_name = elf_strptr(elf, strtabidx, sym->st_name);
    progs.try_emplace(sym_name, sym_name, prog_type, sym->st_value);

    bpf_progs = (struct bpf_program *)realloc(
        bpf_progs, (nr_progs + 1) * sizeof(*bpf_progs));
    if (!bpf_progs) {
      std::cerr << "sec " << scn_name
                << ": failed to alloc memory for new program " << sym_name
                << std::endl;
      return -ENOMEM;
    }
    obj->programs = bpf_progs;
    bpf_prog = &bpf_progs[nr_progs];

    if (iu_object__init_prog(obj, bpf_prog, sym_name, elf_ndxscn(scn), scn_name,
                             sym->st_value, (char *)data->d_buf + sym->st_value,
                             sym->st_size, sec_def))
      return -1;

    nr_progs++;
    obj->nr_programs = nr_progs;
  }
  qsort(obj->programs, obj->nr_programs, sizeof(*obj->programs), cmp_progs);
  return 0;
};

int iu_obj::parse_rela_dyn() {
  int ret;
  Elf64_Shdr *rela_dyn;
  iu_rela_dyn *rela_dyn_data;
  uint64_t rela_dyn_addr, rela_dyn_size, nr_dyn_relas;
  int idx;

  if (!this->rela_dyn_scn)
    return 0;

  rela_dyn = elf64_getshdr(rela_dyn_scn);

  if (!rela_dyn) {
    std::cerr << "elf: failed to get .rela.dyn section" << std::endl;
    return -1;
  }

  rela_dyn_data =
      reinterpret_cast<iu_rela_dyn *>(elf_getdata(rela_dyn_scn, 0)->d_buf);
  rela_dyn_addr = rela_dyn->sh_addr;
  rela_dyn_size = rela_dyn->sh_size;

  if (debug) {
    std::clog << ".rela.dyn offset=" << std::hex << rela_dyn_addr
              << ", .rela.dyn size=" << std::dec << rela_dyn_size << std::endl;
  }

  if (rela_dyn_size % sizeof(iu_rela_dyn)) {
    std::cerr << "elf: ill-formed .rela.dyn section" << std::endl;
    return -1;
  }

  nr_dyn_relas = rela_dyn_size / sizeof(iu_rela_dyn);

  for (idx = 0; idx < nr_dyn_relas; idx++) {
    // Need to skip the map relocs, these are handled differently in the kernel
    if (map_defs.find(rela_dyn_data[idx].addend) != map_defs.end())
      continue;

    if (ELF64_R_TYPE(rela_dyn_data[idx].info) == R_X86_64_RELATIVE) {
      dyn_relas.push_back(rela_dyn_data[idx]);
    } else if (ELF64_R_TYPE(rela_dyn_data[idx].info) == R_X86_64_GLOB_DAT) {
      uint32_t dynsym_idx = ELF64_R_SYM(rela_dyn_data[idx].info);
      Elf_Data *syms = elf_getdata(dynsym_scn, 0);
      size_t strtabidx = elf64_getshdr(dynsym_scn)->sh_link;
      Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + dynsym_idx;
      iu_dyn_sym dyn_sym = {0};
      char *name = strdup(elf_strptr(elf, strtabidx, sym->st_name));

      if (!name) {
        std::cerr << "failed to alloc symbol name" << std::endl;
        return -1;
      }

      dyn_sym.offset = rela_dyn_data[idx].offset;
      dyn_sym.symbol = reinterpret_cast<__u64>(name);

      dyn_syms.push_back(dyn_sym);
    } else {
      std::cerr << "elf: relocation type not supported" << std::endl;
      return -1;
    }
  }

  if (debug) {
    std::clog << ".rela.dyn: " << std::hex << std::endl;
    for (auto &dyn_rela : dyn_relas) {
      std::clog << "0x" << dyn_rela.offset << ", 0x" << dyn_rela.info << ", 0x"
                << dyn_rela.addend << std::endl;
    }
    for (auto &dyn_sym : dyn_syms) {
      std::clog << "0x" << dyn_sym.offset << ", "
                << reinterpret_cast<char *>(dyn_sym.symbol) << std::endl;
    }
    std::clog << std::dec;
  }

  return 0;
}

int iu_obj::parse_elf(struct bpf_object *obj) {
  int ret;

  if (!elf) {
    std::cerr << "elf: failed to open object" << std::endl;
    return -1;
  }

  ret = this->parse_scns(obj);
  ret = ret < 0 ?: this->parse_maps(obj);
  ret = ret < 0 ?: this->parse_progs(obj);
  ret = ret < 0 ?: this->parse_rela_dyn();

  return ret;
}

int iu_obj::fix_maps(struct bpf_object *obj) {
  Elf64_Addr maps_shaddr;
  Elf64_Off maps_shoff;

  if (!this->maps_scn) {
    return 0;
  }

  maps_shaddr = elf64_getshdr(maps_scn)->sh_addr;
  maps_shoff = elf64_getshdr(maps_scn)->sh_offset;

  if (debug) {
    std::clog << ".maps section file offset=0x" << std::hex
              << elf64_getshdr(maps_scn)->sh_offset << std::dec << std::endl;
  }

  if (this->file_size < 0 || reinterpret_cast<int64_t>(this->file_map) < 0) {
    perror("mmap");
    return -1;
  }

  for (auto &def : map_defs) {
    size_t kptr_file_off =
        def.first + offsetof(map_def, kptr) - maps_shaddr + maps_shoff;
    int map_fd;

    if (debug) {
      std::clog << "map_ptr=0x" << std::hex << def.first << std::dec
                << std::endl;
      std::clog << "map_name=\"" << def.second.name << '\"' << std::endl;
    }

    map_fd = def.second.create();
    if (map_fd < 0) {
      perror("bpf_map_create");
      return -1;
    }

    for (int i = 0; i < obj->nr_maps; i++) {
      struct bpf_map *map = &obj->maps[i];
      if (!strcmp(map->name, def.second.name.c_str())) {
        map->fd = map_fd;
        if (debug)
          std::clog << "map_fd added in object" << std::endl;
        break;
      }
    }

    name2map.insert(std::make_pair(def.second.name, &def.second));

    if (debug)
      std::clog << "map_fd=" << map_fd << std::endl;

    val_to_buf<uint64_t>(&this->file_map[kptr_file_off], map_fd);
  }

  return 0;
}

int iu_obj::load(struct bpf_object *obj) {
  int fd;
  auto arr = std::make_unique<uint64_t[]>(map_defs.size());
  union bpf_attr attr = {0};
  int idx = 0, ret = 0;

  // TODO: Will have race condition if multiple objs loaded at same time
  std::ofstream output("rust.out", std::ios::out | std::ios::binary);

  output.write((char *)this->file_map, this->file_size);
  output.close();

  fd = open("rust.out", O_RDONLY);

  for (auto &def : map_defs)
    arr[idx++] = def.first + offsetof(map_def, kptr);

  attr.prog_type = BPF_PROG_TYPE_IU_BASE;
  memcpy(attr.prog_name, "map_test", sizeof("map_test"));
  attr.rustfd = fd;
  attr.license = reinterpret_cast<__u64>("GPL");

  attr.map_offs = reinterpret_cast<__u64>(arr.get());
  attr.map_cnt = map_defs.size();

  attr.dyn_relas = reinterpret_cast<__u64>(dyn_relas.data());
  attr.nr_dyn_relas = dyn_relas.size();

  attr.dyn_syms = reinterpret_cast<__u64>(dyn_syms.data());
  attr.nr_dyn_syms = dyn_syms.size();

  ret = bpf(BPF_PROG_LOAD_IU_BASE, &attr, sizeof(attr));

  if (ret < 0) {
    perror("bpf_prog_load_iu_base");
    return -1;
  }

  this->prog_fd = ret;

  if (debug)
    std::clog << "Base program loaded, fd = " << ret << std::endl;

  if (remove("rust.out") < 0) {
    perror("remove");
    goto close_fds;
  }

  for (auto &it : progs) {
    attr.prog_type = it.second.prog_type;
    strncpy(attr.prog_name, it.second.name.c_str(), sizeof(attr.prog_name) - 1);
    attr.base_prog_fd = this->prog_fd;
    attr.prog_offset = it.second.offset;
    attr.license = (__u64) "GPL";
    it.second.fd = bpf(BPF_PROG_LOAD_IU, &attr, sizeof(attr));

    if (it.second.fd < 0) {
      perror("bpf_prog_load_iu");
      goto close_fds;
    }

    for (int i = 0; i < obj->nr_programs; i++) {
      struct bpf_program *prog = &obj->programs[i];
      if (!strcmp(prog->name, it.second.name.c_str())) {
        prog->instances.fds = (int *)malloc(sizeof(int));
        prog->instances.nr = 1;
        prog->instances.fds[0] = it.second.fd;
        if (debug)
          std::clog << "prog_fd added in object" << std::endl;
        break;
      }
    }

    if (debug)
      std::clog << "Program " << it.first << " loaded, fd = " << it.second.fd
                << std::endl;
  }
  obj->loaded = true;
  return ret;

close_fds:
  for (auto &it : progs) {
    if (it.second.fd >= 0)
      close(it.second.fd);
  }
  close(this->prog_fd);
  return -1;
}

int iu_obj::find_map_by_name(const char *name) const {
  auto it = name2map.find(name);
  return it != name2map.end() ? it->second->map_fd : -1;
}

int iu_obj::find_prog_by_name(const char *name) const {
  auto it = progs.find(name);
  return it != progs.end() ? it->second.fd : -1;
}

void iu_set_debug(const int val) { debug = val; }

int iu_obj_load(const char *file_path, struct bpf_object *bpf_obj) {
  int ret;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    std::cerr << "elf: failed to init libelf" << std::endl;
    return -1;
  }

  auto obj = std::make_unique<iu_obj>(file_path, bpf_obj);

  ret = obj->parse_elf(bpf_obj);
  ret = ret ?: obj->fix_maps(bpf_obj);
  ret = ret ?: obj->load(bpf_obj);

  if (ret >= 0)
    objs[ret] = std::move(obj);

  return ret;
}

int iu_obj_close(int prog_fd) {
  auto it = objs.find(prog_fd);
  if (it != objs.end()) {
    objs.erase(it);
    return 0;
  }

  return -1;
}

int iu_obj_get_map(int prog_fd, const char *map_name) {
  auto it = objs.find(prog_fd);
  return it != objs.end() ? it->second->find_map_by_name(map_name) : -1;
}

int iu_obj_get_prog(int prog_fd, const char *prog_name) {
  auto it = objs.find(prog_fd);
  return it != objs.end() ? it->second->find_prog_by_name(prog_name) : -1;
}

struct bpf_object *iu_object__open(char *path) {
  struct bpf_object *obj;
  int base_fd;

  if (!path)
    return NULL;
  obj = (struct bpf_object *)calloc(1, sizeof(struct bpf_object) +
                                           strlen(path) + 1);
  if (!obj) {
    std::cerr << "alloc memory failed for " << path << std::endl;
    return NULL;
  }

  strcpy(obj->path, path);
  strncpy(obj->name, basename(path), sizeof(obj->name) - 1);
  obj->name[sizeof(obj->name) - 1] = 0;

  obj->efile.obj_buf = NULL;
  obj->efile.obj_buf_sz = 0;
  obj->efile.maps_shndx = -1;
  obj->efile.btf_maps_shndx = -1;
  obj->efile.data_shndx = -1;
  obj->efile.rodata_shndx = -1;
  obj->efile.bss_shndx = -1;
  obj->efile.st_ops_shndx = -1;
  obj->kconfig_map_idx = -1;
  obj->rodata_map_idx = -1;

  __u32 major, minor, patch;
  struct utsname info;

  uname(&info);
  if (sscanf(info.release, "%u.%u.%u", &major, &minor, &patch) != 3)
    return NULL;
  obj->kern_version =
      (((major) << 16) + ((minor) << 8) + ((patch) > 255 ? 255 : (patch)));

  INIT_LIST_HEAD(&obj->list);
  list_add(&obj->list, &bpf_objects_list);

  base_fd = iu_obj_load(path, obj);
  iu_object__elf_finish(obj);

  if (base_fd < 0) {
    bpf_object__close(obj);
    return NULL;
  }

  return obj;
}

struct bpf_object *
iu_object__open_file(char *path, const struct bpf_object_open_opts *opts) {
  return iu_object__open(path);
}

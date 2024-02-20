#include <bpf.h>
#include <errno.h>
#include <libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#define EXE "./blocker_kern.o"

int main(int argc, char **argv) {
  struct bpf_object *obj;
  struct bpf_program *prog;
  int prog_fd;
  int ifindex;
  int err;
  int map_progs_xdp_fd;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <interface index>\n", argv[0]);
    return 1;
  }

  // Get network interface index
  ifindex = atoi(argv[1]);

  // Open BPF object file
  obj = bpf_object__open(EXE);
  if (libbpf_get_error(obj)) {
    perror("bpf_object__open");
    return 1;
  }

  // Load BPF program
  err = bpf_object__load(obj);
  if (err) {
    perror("bpf_object__load");
    return 1;
  }

  map_progs_xdp_fd = bpf_object__find_map_fd_by_name(obj, "port_map");
  if (map_progs_xdp_fd < 0) {
    fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
    return 1;
  }

  // Find the XDP program
  prog = bpf_object__find_program_by_name(obj, "xdp_filter_by_port");
  if (!prog) {
    fprintf(stderr, "bpf_object__find_program_by_title failed\n");
    return 1;
  }

  prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    perror("bpf_program__fd");
    return 1;
  }

  // Attach the BPF program
  int xdp_flags = 0;
  xdp_flags |= XDP_FLAGS_SKB_MODE;

  if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
    fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n",
            ifindex);
    return 1;
  } else {
    printf("Main BPF program attached to XDP on interface %d\n", ifindex);
  }

  int quit = 0;
  int sig = 0;
  sigset_t signal_mask;
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGINT);
  sigaddset(&signal_mask, SIGTERM);
  while (!quit) {
    err = sigwait(&signal_mask, &sig);
    if (err != 0) {
      fprintf(stderr, "Error: Failed to wait for signal\n");
      exit(EXIT_FAILURE);
    }

    switch (sig) {
      case SIGINT:
      case SIGTERM:
        quit = 1;
        break;

      default:
        fprintf(stderr, "Unknown signal\n");
        break;
    }
  }

  return 0;
}

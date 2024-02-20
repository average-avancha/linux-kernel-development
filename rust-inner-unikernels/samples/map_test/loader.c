#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <linux/unistd.h>

#include "libiu.h"
#include <libbpf.h>

#define EXE "./target/x86_64-unknown-linux-gnu/release/map_test"

int main(void)
{
	int trace_pipe_fd;
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;

	iu_set_debug(1); // enable debug info

	obj = iu_object__open(EXE);
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		exit(1);
	}

	prog = bpf_object__find_program_by_name(obj, "iu_prog1");
	if (!prog) {
 		fprintf(stderr, "Program not found\n");
 		exit(1);
 	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	trace_pipe_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/trace_pipe",
		O_RDONLY);

	for (;;) {
        char c;
        if (read(trace_pipe_fd, &c, 1) == 1)
            putchar(c);
    }

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}

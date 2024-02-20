#ifndef LIBIU_H
#define LIBIU_H

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_object;
struct bpf_object_open_opts;

void iu_set_debug(const int val);

int iu_obj_load(const char *file_path, struct bpf_object *obj);
int iu_obj_close(int prog_fd);
int iu_obj_get_map(int prog_fd, const char *map_name);
int iu_obj_get_prog(int prog_fd, const char *prog_name);

struct bpf_object *iu_object__open(char *path);
struct bpf_object *iu_object__open_file(char *path, const struct bpf_object_open_opts *opts);

#ifdef __cplusplus
}
#endif

#endif // LIBIU_H

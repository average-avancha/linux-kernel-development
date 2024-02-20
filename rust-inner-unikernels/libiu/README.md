# LIBIU

This is the temporary implementation of the inner-unikernel userspace library
for loading programs. We might eventually move this into `libbpf`.

Currently the Makefile does not have an `install` target and therefore does not
install the compiled library object to the system path. The following step is
needed to use the shared object of the library:
```console
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/path/to/inner_unikernels/libiu'
```

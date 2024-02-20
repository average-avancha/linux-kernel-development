#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#define FACTORIAL_COUNT 100000000ul
#define READ_SIZE 10000 * sizeof(char) //bytes
#define STATUS_FILEPATH "/proc/mp2/status"

int factorial(int n);
int read_proc_fs(const char * filepath);
int register_process(int pid, unsigned long period, unsigned long process_time);
int yield_process(int pid);
int deregister_process(int pid);
int calc_job_time(int n);
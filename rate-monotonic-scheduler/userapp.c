#include "userapp.h"

int main(int argc, char *argv[])
{
    if(argc != 3){
        printf("Error: Invalid number of arguments. Expect 2: PERIOD and NUMBER OF JOBS for the application to run.\n");
        return -1;
    }
    
    char * temp;
    unsigned long period = strtoul(argv[1], &temp, 10);
    unsigned long number_of_jobs = strtoul(argv[2], &temp, 10);
    
    //Error handling for strtoul
    if(period <= 0 | period == ULONG_MAX| number_of_jobs <= 0 | number_of_jobs == ULONG_MAX){
        printf("Error: Invalid arguments. Expect positive integers in range for PERIOD and NUMBER OF JOBS.\n");
        return -2;
    }


    int pid = getpid();
    printf("PID: %d\n", pid);

    unsigned long processing_time = calc_job_time(FACTORIAL_COUNT);
    printf("Processing time: %lu\n", processing_time);

    register_process(pid, period, processing_time);
    //Implement list of proceses
    read_proc_fs(STATUS_FILEPATH);
    
    struct timespec t0;
    clock_gettime(CLOCK_REALTIME, &t0); 
    
    yield_process(pid);

    int jobs = number_of_jobs;
    while(jobs > 0){
        struct timespec wakeup_time, process_time; 
        clock_gettime(CLOCK_REALTIME, &wakeup_time);
        wakeup_time.tv_nsec = wakeup_time.tv_nsec - t0.tv_nsec;
        wakeup_time.tv_sec = wakeup_time.tv_sec - t0.tv_sec;

        factorial(FACTORIAL_COUNT);
        
        clock_gettime(CLOCK_REALTIME, &process_time);
        process_time.tv_nsec = process_time.tv_nsec - wakeup_time.tv_nsec;
        process_time.tv_sec = process_time.tv_sec - wakeup_time.tv_sec;
        
        yield_process(pid);
        jobs--;
    }
    deregister_process(pid);
    read_proc_fs(STATUS_FILEPATH);
}

int factorial(int n){
    if(n <= 0){
        return -1;
    }
    
    int i, result = 1;
    for(i = n; 0 < i; i--){
        result *= i;
    }
    return result;

}

int read_proc_fs(const char * filepath){
    char read_buffer[READ_SIZE];
    
    //Register current process
    FILE *fp = fopen(filepath, "r");
    if(fp == NULL){
        printf("Error: Cannot open file\n");
        return -1;
    }

    if(fgets(read_buffer, READ_SIZE, fp) != NULL){
        printf("READ:%s", read_buffer);
    }
    fclose(fp);
    
    return 0;
}

int register_process(int pid, unsigned long period, unsigned long processing_time){
    printf("Writing R, %d, %lu, %lu to %s:\n", pid, period, processing_time, STATUS_FILEPATH);
    
    //Register current process
    FILE *fp = fopen(STATUS_FILEPATH, "w");
    if(fp == NULL){
        printf("Error: Cannot open file\n");
        return -1;
    }

    fprintf(fp, "R,%d,%lu,%lu\n", pid, period, processing_time);
    fclose(fp);
    

    return 0;
}

int yield_process(int pid){
    printf("Writing Y, %d to %s:\n", pid, STATUS_FILEPATH);

    //Yield current process
    FILE *fp = fopen(STATUS_FILEPATH, "w");
    if(fp == NULL){
        printf("Error: Cannot open file\n");
        return -1;
    }

    fprintf(fp, "Y,%d\n", pid);
    fclose(fp);
    
    return 0;
}

int deregister_process(int pid){
    printf("Writing D, %d to %s:\n", pid, STATUS_FILEPATH);
    
    //Deregister current process
    FILE *fp = fopen(STATUS_FILEPATH, "w");
    if(fp == NULL){
        printf("Error: Cannot open file\n");
        return -1;
    }

    fprintf(fp, "D,%d\n", pid);
    fclose(fp);

    return 0;
}

int calc_job_time(int n){
    struct timeval t0, t1;
    
    gettimeofday(&t0, NULL);
    factorial(n);
    gettimeofday(&t1, NULL);

    printf("t0(ms): %ld\n", t0.tv_sec * 1000 + t0.tv_usec / 1000);
    printf("t1(ms): %ld\n", t1.tv_sec * 1000 + t1.tv_usec / 1000);
    printf("Time(ms): %ld milliseconds\n", (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_usec - t0.tv_usec) / 1000);
    return (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_usec - t0.tv_usec) / 1000;
}
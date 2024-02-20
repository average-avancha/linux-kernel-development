#define LINUX

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <uapi/linux/sched/types.h>
#include "mp2_given.h"

MODULE_AUTHOR("Ritvik Avancha <rra2@illinois.edu>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CS-423 MP2");

#define DEBUG 1
#define DIRNAME "mp2"
#define FILEMODE 0666
#define FILENAME "status"

static ssize_t mp2_read(struct file * filp, char __user * usr_buf, size_t count, loff_t * offp);
static ssize_t mp2_write(struct file * filp, const char __user * usr_buf, size_t count, loff_t * offp);
static void mp2_timer_callback(struct timer_list * timer);
static void mp2_timer_work_handler(struct work_struct *work);

enum task_state {
        READY,
        RUNNING,
        SLEEPING,
};

struct mp2_task_struct {
        struct list_head list;
        unsigned int pid;
	unsigned long period;
	unsigned long processing_time;
        unsigned long deadline_jiff;
        struct task_struct * task;
        struct timer_list wakeup_timer;
        enum task_state state;
};


static struct proc_ops proc_fops = {
	.proc_read = mp2_read,
	.proc_write = mp2_write,
};


// mp2_process_list - Linked list of processes currently registered with the RMS scheduler.
static LIST_HEAD(mp2_process_list);
static struct kmem_cache * mp2_task_struct_cachep;

static struct mp2_task_struct * mp2_curr_task = NULL;
struct task_struct *dispatch_thread = NULL;
static spinlock_t mp2_proc_list_lock;

static DECLARE_WORK(mp2_timer_work, mp2_timer_work_handler);


/* mp2_dispatcher - Called by yield or timer interrupt handler to schedule the next process.
 * 
 * @new_process - 1 if the process is new, 0 if the process is an old running task.
 * 
 */
static int mp2_dispatcher(void * data)
{

        struct sched_attr attr;
        struct mp2_task_struct * task_i, * temp_task, * highest_priority_task;
        unsigned long flags, min_period;
        
        #ifdef DEBUG
        printk(KERN_ALERT "...MP2 DISPATCHER STARTING...\n");
        #endif

        while(!kthread_should_stop()){

                spin_lock_irqsave(&mp2_proc_list_lock, flags);
                #ifdef DEBUG
                printk("......MP2 DISPATCHER | Acquired lock\n");
                #endif

                min_period = ULONG_MAX;
                highest_priority_task = NULL;
                if(mp2_curr_task != NULL){
                        // mp2_curr_task->state = READY;
                        min_period = mp2_curr_task->period;
                        highest_priority_task = mp2_curr_task;
                }

                //critical section
                list_for_each_entry_safe(task_i, temp_task, &mp2_process_list, list){
                        if((task_i->state == READY) && (task_i->period < min_period)){
                                min_period = task_i->period;
                                highest_priority_task = task_i;
                        }
                }

                
                if(highest_priority_task != NULL && highest_priority_task != mp2_curr_task){
                        // Preempt the current task
                        if (mp2_curr_task) {
                                attr.sched_policy = SCHED_NORMAL;
                                attr.sched_priority = 0;
                                sched_setattr_nocheck(mp2_curr_task->task, &attr);
                                mp2_curr_task->state = READY;
                        }
                        
                        // Switch to the highest priority task
                        attr.sched_policy = SCHED_FIFO;
                        attr.sched_priority = 99;
                        sched_setattr_nocheck(highest_priority_task->task, &attr);
                        
                        highest_priority_task->state = RUNNING;
                        mp2_curr_task = highest_priority_task;
                        
                        wake_up_process(highest_priority_task->task);
                        
                        
                        #ifdef DEBUG
                        printk("......MP2 DISPATCHER... | Dispatching PID: %d\n", highest_priority_task->pid);
                        #endif

                } 
                // no tasks ready
                // else if(highest_priority_task == NULL){

                // }

                set_current_state(TASK_INTERRUPTIBLE);
                
                #ifdef DEBUG
                printk("......MP2 DISPATCHER | Releasing lock\n");
                #endif
                spin_unlock_irqrestore(&mp2_proc_list_lock, flags);
                
                schedule();

        }

        #ifdef DEBUG
        printk(KERN_ALERT "...MP2 DISPATCHER ENDING...\n");
        #endif

        return -1;
}

/* mp2_timer_callback - interrupt handler is called when the timer expires.
 * The timer handler as the top half should change the task state to READY and 
 * queue up the bottom half work handler to wake up the dispatching thread.
 * 
 * 
 * 
 */
static void mp2_timer_callback(struct timer_list * timer)
{
        unsigned long flags;
        struct mp2_task_struct * callback_task;
        struct mp2_task_struct * task_i, * temp_task;

        #ifdef DEBUG
        printk(KERN_ALERT "...MP2 TIMER CALLBACK STARTING...\n");
        #endif

        spin_lock_irqsave(&mp2_proc_list_lock, flags);
        #ifdef DEBUG
        printk("......MP2 TIMER CALLBACK | Acquired lock\n");
        #endif

        callback_task = from_timer(callback_task, timer, wakeup_timer);

        #ifdef DEBUG
        printk(KERN_ALERT "......MP2 TIMER CALLBACK | callback_task: %p\n", callback_task);
        #endif 

        if(callback_task != NULL){
                #ifdef DEBUG
                printk(KERN_ALERT "......MP2 TIMER CALLBACK | callback_task->pid: %d\n", callback_task->pid);
                #endif

                //critical section
                list_for_each_entry_safe(task_i, temp_task, &mp2_process_list, list){
                        if(task_i->pid == callback_task->pid){
                                callback_task->state = READY;
                                callback_task->deadline_jiff += msecs_to_jiffies(callback_task->period);
                                mod_timer(timer, callback_task->deadline_jiff);
                                // mod_timer(timer, msecs_to_jiffies(callback_task->period) + jiffies);
                        }
                }
                
        }
        #ifdef DEBUG
        printk("......MP2 TIMER CALLBACK | Releasing lock\n");
        #endif
        spin_unlock_irqrestore(&mp2_proc_list_lock, flags);
        
        #ifdef DEBUG
        printk(KERN_ALERT "......MP2 TIMER CALLBACK | dispatch_thread: %p\n", dispatch_thread);
        #endif 
        //wake up dispatching thread
        wake_up_process(dispatch_thread);
        
        
        #ifdef DEBUG
        printk(KERN_ALERT "...MP2 TIMER CALLBACK DONE...\n");
        #endif

}


/* mp2_timer_work_handler - Functions as the bottom half of the timer interrupt handler.
 * The work handler should wake up the dispatching thread.
 * 
 * 
 * 
 */
static void mp2_timer_work_handler(struct work_struct *work)
{
        #ifdef DEBUG
        printk(KERN_ALERT "...MP2 TIMER WORK HANDLER STARTING...\n");
        #endif

        

        wake_up_process(dispatch_thread);

        #ifdef DEBUG
        printk(KERN_ALERT "...MP2 TIMER WORK HANDLER DONE...\n");
        #endif
        

}


/* mp2_admission_control - Called when an application wants to register a process to the RMS scheduler.
 * 
 * Return 0: if the process can be scheduled without missing any deadlines.
 * Return -1: if the process cannot be scheduled without missing any deadlines.
 * 
 */
static int mp2_admission_control(unsigned long period, unsigned long processing_time)
{
        struct mp2_task_struct * task_i, * temp_task;
        unsigned long flags, total_period, total_processing_time;
        int rv;

        #ifdef DEBUG
        printk("...MP2 ADMISSION CONTROL STARTING... | Period(ms): %lu, Processing Time(ms): %lu\n", period, processing_time);
        #endif

        total_period = period;
        total_processing_time = processing_time;

        spin_lock_irqsave(&mp2_proc_list_lock, flags);
        #ifdef DEBUG
        printk("......MP2 ADMISSION CONTROL | Acquired lock\n");
        #endif
        //critical section
        list_for_each_entry_safe(task_i, temp_task, &mp2_process_list, list){
                total_period += task_i->period;
                total_processing_time += task_i->processing_time;
        }

        #ifdef DEBUG
        printk("......MP2 ADMISSION CONTROL | %ld <= %d\n", (total_processing_time * 1000)/total_period, 693);
        #endif
        #ifdef DEBUG
        printk("......MP2 ADMISSION CONTROL | Releasing lock\n");
        #endif
        spin_unlock_irqrestore(&mp2_proc_list_lock, flags);

        rv = 1;
        if((total_processing_time * 1000)/total_period <= 693){ //total_processing_time/total_period <= 0.693 [fixed point arithmetic]
                rv = 0;
        }

        #ifdef DEBUG
        printk("...MP2 ADMISSION CONTROL DONE... | Period(ms): %lu, Processing Time(ms): %lu, return value: %d\n", period, processing_time, rv);
        #endif

        return rv;
}


/* mp2_registration - Called when an application wants to register a process to the RMS scheduler.
 * The admission control only allows process registration if the new process can be scheduled without 
 * missing any existing deadlines. 
 * 
 * Returns 0: if the process was successfully registered.
 * Returns 1: if the process did not pass admission control and wasn't registered.
 * Returns -1: if the process was not registered due to PID < 0.
 * 
 * NOTE: This case has to be handled by the proc file write callback
 */
static int mp2_registration(unsigned int pid, unsigned long period, unsigned long processing_time)
{
        int rv;
        struct mp2_task_struct * new_proc;
        struct mp2_task_struct * temp_task, * i_task;
        unsigned long flags;
        
        #ifdef DEBUG
        printk("...MP2 REGISTRATION STARTING... | PID: %u, Period: %lu, Processing Time: %lu\n", pid, period, processing_time);
        #endif

        // check to handle negative pid case
        if(pid < 0){
                #ifdef DEBUG
                printk("......MP2 REGISTRATION | pid < 0 - PID: %u, Period: %lu, Processing Time: %lu\n", pid, period, processing_time);
                #endif
                return -1;
        }

        if(mp2_admission_control(period, processing_time) != 0){
                pr_warn("Processing time:%lu could not be scheduled within period: %lu\n", processing_time, period);
                return (int)1;
        }

        rv = 0;
        flags = 0;

        spin_lock_irqsave(&mp2_proc_list_lock, flags);
        #ifdef DEBUG
        printk("......MP2 REGISTRATION | Acquired lock\n");
        #endif
        //critical section
        list_for_each_entry_safe(i_task, temp_task, &mp2_process_list, list){
                if(i_task->pid == pid){
                        #ifdef DEBUG
                        printk("......MP2 REGISTRATION | Process already scheduled - PID: %u\n", pid);
                        #endif
                        // pr_warn("Task already registered\n");
                        goto unlock_list;  
                }
        }

        new_proc = kmem_cache_alloc(mp2_task_struct_cachep, GFP_KERNEL);
	if(new_proc == NULL){
		pr_warn("Error allocating memory for new_proc\n");
                rv = -1;
		goto unlock_list;
	}
	
	new_proc->pid = pid;
	new_proc->period = period;
        new_proc->processing_time = processing_time;
        new_proc->deadline_jiff = jiffies + msecs_to_jiffies(period);
        new_proc->state = SLEEPING;
	INIT_LIST_HEAD(&new_proc->list);
        new_proc->task = find_task_by_pid((unsigned int)pid);
        if(!new_proc->task) {
                pr_warn("Error finding task with pid: %u\n", pid);
                rv = -1;
                goto unlock_list;
        }

        set_current_state(TASK_UNINTERRUPTIBLE);
        
        timer_setup(&new_proc->wakeup_timer, &mp2_timer_callback, 0);

        //critical section
	list_add_tail(&new_proc->list, &mp2_process_list);

unlock_list:
        #ifdef DEBUG
        printk("......MP2 REGISTRATION | Releasing lock\n");
        #endif
        spin_unlock_irqrestore(&mp2_proc_list_lock, flags);
        
        #ifdef DEBUG
        printk("...MP2 REGISTRATION DONE...\n");
        #endif

        return rv;
}


/* mp2_yield - Called by an application has completed its period.
 * The yeild function should put the process to sleep and setup a 
 * wakeup timer.  
 * 
 * NOTE: This case has to be handled by the proc file write callback
 */
static int mp2_yield(unsigned int pid)
{

        struct mp2_task_struct * temp_task, * i_task, * yield_task;
        unsigned long flags;
        
        #ifdef DEBUG
        printk("...MP2 YIELD STARTING...\n");
        #endif

        spin_lock_irqsave(&mp2_proc_list_lock, flags);
        #ifdef DEBUG
        printk("......MP2 YIELD | Acquired lock\n");
        #endif
        //critical section
        yield_task = NULL;
        list_for_each_entry_safe(i_task, temp_task, &mp2_process_list, list){
                if(i_task->pid == pid){
                        yield_task = i_task;
                        break;  
                }
        }

        if(yield_task != NULL){
                if(yield_task->deadline_jiff > jiffies){
                        #ifdef DEBUG
                        printk("......MP2 YIELD | yield_task->deadline_jiff: %lu, jiffies: %lu\n", yield_task->deadline_jiff, jiffies);
                        #endif

                        yield_task->state = SLEEPING;
                        set_current_state(TASK_UNINTERRUPTIBLE);
                        mod_timer(&(yield_task->wakeup_timer), yield_task->deadline_jiff);
                }
                else{
                        mod_timer(&(yield_task->wakeup_timer), jiffies);
                }
        }
        #ifdef DEBUG
        printk("......MP2 YIELD | Releasing lock\n");
        #endif
        spin_unlock_irqrestore(&mp2_proc_list_lock, flags);

        #ifdef DEBUG
        printk("...MP2 YIELD DONE...\n");
        #endif

        return (int)0;
}


/* mp2_deregistration - Called when an application is finished using the RMS scheduler.
 * 
 * NOTE: This case has to be handled by the proc file write callback
 */
static int mp2_deregistration(unsigned int pid)
{
        struct mp2_task_struct * task_i, * temp_task;
        unsigned long flags;

        #ifdef DEBUG
        printk("...MP2 DE-REGISTRATION STARTING...\n");
        #endif
        
        spin_lock_irqsave(&mp2_proc_list_lock, flags);
        #ifdef DEBUG
        printk("......MP2 DE-REGISTRATION | Acquired lock\n");
        #endif
        list_for_each_entry_safe(task_i, temp_task, &mp2_process_list, list){
                
                #ifdef DEBUG
                printk("......MP2 DE-REGISTRATION: task_i->pid: %d\n", task_i->pid);
                #endif

                if(task_i->pid == pid){
                        del_timer(&task_i->wakeup_timer);
                        list_del(&task_i->list);
                        kmem_cache_free(mp2_task_struct_cachep, task_i);
                        break;
                }
        }
        #ifdef DEBUG
        printk("......MP2 DE-REGISTRATION | Releasing lock\n");
        #endif
        spin_unlock_irqrestore(&mp2_proc_list_lock, flags);

        #ifdef DEBUG
        printk("...MP2 DE-REGISTRATION DONE...\n");
        #endif

        return (int)0;
}

/* mp2_read - Called when an application triggers a read callback.
 * The read callback should return a list of all the processes currently 
 * registered with the RMS scheduler.
 * 
 * 
 */
static ssize_t mp2_read(struct file * filp, char __user * usr_buf, size_t count, loff_t * offp)
{
        char * buf;
	int bytes_to_write, bytes_not_copied, bytes_written, cur_proc_size;
	struct mp2_task_struct * temp_proc, * curr_proc;
	unsigned long flags;

        #ifdef DEBUG
        printk("...MP2 READ CALLBACK STARTING...\n");
        #endif
        
        if(*offp != 0){
                #ifdef DEBUG
                printk("......MP2 READ CALLBACK | *offp != 0 \n");
                #endif
		return 0;
	}

	buf = (char *)kmalloc(count, GFP_KERNEL);
	bytes_to_write = 0;
	
	spin_lock_irqsave(&mp2_proc_list_lock, flags);
        #ifdef DEBUG
        printk("......MP2 READ CALLBACK | Acquired lock\n");
        #endif
	//critical section
	list_for_each_entry_safe(curr_proc, temp_proc, &mp2_process_list, list){

                #ifdef DEBUG
                printk("......MP2 READ CALLBACK | curr_proc: %p, curr_proc->pid: %d, curr_proc->period: %lu, curr_proc->processing_time: %lu\n", curr_proc, curr_proc->pid, curr_proc->period, curr_proc->processing_time);
                #endif
		
		// if(*offp + sizeof(curr_proc->pid) + sizeof(curr_proc->period) + sizeof(curr_proc->processing_time) > count){
		// 	break;
		// }
                cur_proc_size = snprintf(buf + *offp, count, "%d: %lu, %lu\n", curr_proc->pid, curr_proc->period, curr_proc->processing_time);
                if(cur_proc_size + bytes_to_write >= count){
                        #ifdef DEBUG
                        printk("......MP2 READ CALLBACK | avoiding buffer overflow (cur_proc_size + bytes_to_write: %d >= buffer_size: %ld)\n", cur_proc_size + bytes_to_write, count);
                        #endif
                        goto unlock_list;
                }
                bytes_to_write += cur_proc_size;
		if(bytes_to_write < 0){
			pr_warn("Error: Writing to buffer failed\n");
                        goto unlock_list;
		}
		*offp += bytes_to_write;
	}
unlock_list:
        #ifdef DEBUG
        printk("......MP2 READ CALLBACK | Releasing lock\n");
        #endif
	spin_unlock_irqrestore(&mp2_proc_list_lock, flags);

	bytes_not_copied = copy_to_user(usr_buf, buf, count);
	bytes_written = bytes_to_write - bytes_not_copied;

        #ifdef DEBUG
        printk("......MP2 READ CALLBACK | read_buffer: %s\n", buf);
        #endif

	kfree(buf);

        #ifdef DEBUG
        printk("...MP2 READ CALLBACK DONE...\n");
        #endif

	return bytes_written;
}

/* mp2_write - Called when an application triggers a write callback.
 * The write callback should invoke the one of three cases:
 * 1. Process registration
 * 2. Process yielding
 * 3. Process deregistration
 * 
 * Return the number of bytes written to the proc file.
 * 
 * if the number of bytes written is less than the number of bytes requested (count),
 * then the user program will likely just retry writing the remaining bytes.
 * 
 * 
 */
static ssize_t mp2_write(struct file * filp, const char __user * usr_buf, size_t count, loff_t * offp)
{
        int argc, rv;
        unsigned int pid;
        char * ker_buf, * token, * op;
        unsigned long period, processing_time, ret;

        #ifdef DEBUG
        printk("...MP2 WRITE CALLBACK STARTING...\n");
        #endif


        if(*offp != 0) {

                #ifdef DEBUG
                printk("......MP2 WRITE CALLBACK | *offp != 0\n");
                #endif
                return count;
        }

        ker_buf = (char *)kmalloc(count, GFP_KERNEL);


        if(copy_from_user(ker_buf, usr_buf, count) != 0) {
                printk("Error copying from user\n");
                ret = -EFAULT;
                goto cleanup_buf;
        }
        *offp += count;
        ret = count;

        if(ker_buf[count - 1] == '\n'){
		ker_buf[count - 1] = '\0';
	}

        #ifdef DEBUG
        printk("......MP2 WRITE CALLBACK | filp: %p, ker_buf: %s, count: %zu, offp: %lld\n", filp, ker_buf, count, *offp);
        #endif

        argc = 0;
        while ((token = strsep(&ker_buf, ",")) != NULL) {
// #ifdef DEBUG
//                 printk("argc: %d\n", argc);
//                 printk("Token: %s\n", token);
// #endif
                if(argc == 0){
                        op = token;
                }
                else if(argc == 1){
                        rv = kstrtoint(token, 10, &pid);
                        if(rv != 0){
                                pr_warn("Error: Invalid PID\n");
                                ret = -EINVAL;
                                goto cleanup_buf;
                        }
                }
                else if(argc == 2){
                        rv = kstrtoul(token, 10, &period);
                        if(rv != 0){
                                pr_warn("Error: Invalid period\n");
                                ret = -EINVAL;
                                goto cleanup_buf;
                        }
                }
                else if(argc == 3){
                        rv = kstrtoul(token, 10, &processing_time);
                        if(rv != 0){
                                pr_warn("Error: Invalid processing time\n");
                                ret = -EINVAL;
                                goto cleanup_buf;
                        }
                }
                else{
                        pr_warn("Error: Invalid number of arguments\n");
                        ret = -EINVAL;
                        goto cleanup_buf;
                }
                argc += 1;
                
        }
// #ifdef DEBUG
//         printk("op[0]:%c , op:%s \n", op[0], op);
// #endif

        switch (op[0]){
                case 'R':
                        ret = mp2_registration(pid, period, processing_time);
                        break;
                case 'Y':
                        ret = mp2_yield(pid);
                        break;
                case 'D':
                        ret = mp2_deregistration(pid);
                        break;
                default:
                        printk("Error: Invalid command\n");
                        ret = -EINVAL;
                        break;
        }
        
cleanup_buf:
        kfree(ker_buf);

        #ifdef DEBUG
        printk("...MP2 WRITE CALLBACK DONE...\n");
        #endif

        return ret;
}

/* mp2_init - Called when module is loaded
 * 
 * 
 * 
 */
int __init mp2_init(void)
{
	struct proc_dir_entry * parent, * fp;

        #ifdef DEBUG
	printk("...MP2 MODULE LOADING...\n");
        #endif
	
	//Create a "mp2" directory under "/proc"
	parent = proc_mkdir_mode(DIRNAME, FILEMODE, NULL);
	if (parent == NULL) {
		pr_warn("Error creating mp2/ directory\n");
		return -1;
	}
	//Create a "status" file under "/proc/mp2"
	fp = proc_create(FILENAME, FILEMODE, parent, &proc_fops);
	if(fp == NULL){
		pr_warn("Error creating status file\n");
		return -2;
	}

        mp2_task_struct_cachep = kmem_cache_create("mp2_task_struct", sizeof(struct mp2_task_struct), SLAB_HWCACHE_ALIGN, 0, NULL);
        dispatch_thread = kthread_create(&mp2_dispatcher, NULL, "mp2_dispatch_thread");

        #ifdef DEBUG
	printk(KERN_ALERT "...MP2 MODULE LOADED...\n");
        #endif

	return 0;
}


/* mp2_exit - Called when module is unloaded
 * 
 * 
 * 
 */
void __exit mp2_exit(void)
{
        struct mp2_task_struct * task_i, * temp_proc;
        unsigned long flags;

        #ifdef DEBUG
	printk(KERN_ALERT "...MP2 MODULE UNLOADING...\n");
        #endif
        
        spin_lock_irqsave(&mp2_proc_list_lock, flags);

        kthread_stop(dispatch_thread);


	list_for_each_entry_safe(task_i, temp_proc, &mp2_process_list, list){
                del_timer(&task_i->wakeup_timer);
                list_del(&task_i->list);
                kmem_cache_free(mp2_task_struct_cachep, task_i);
        }
        

        kmem_cache_destroy(mp2_task_struct_cachep);
        if( remove_proc_subtree(DIRNAME, NULL) != 0 ) {
                printk("Error removing mp2/ directory\n");
        }
        spin_unlock_irqrestore(&mp2_proc_list_lock, flags);

        #ifdef DEBUG
	printk(KERN_ALERT "...MP2 MODULE UNLOADED...\n");
        #endif
}


// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);

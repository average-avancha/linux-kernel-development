#define LINUX

// #include <linux/jiffies.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <uapi/linux/sched/types.h>

#include "mp3_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rra2");
MODULE_DESCRIPTION("CS-423 MP3");

#define DEBUG 1
#define DEV_MAJOR_NUM 423
#define DEV_MINOR_NUM 0
#define DEV_NAME "char_dev"
#define DIRNAME "mp3"
#define FILEMODE 0666
#define FILENAME "status"
#define PAGE_COUNT 128
#define MEM_BUF_SIZE (PAGE_SIZE * PAGE_COUNT)
#define SAMPLING_PERIOD_ms 50 // (1000 ms)/(20 samples)
#define THRESH_SAMPLING_PERIOD_ms 25

struct mp3_task_struct {
	struct list_head list;
	struct task_struct * task;
	unsigned int pid;
	unsigned long min_flt; 
	unsigned long maj_flt;
	unsigned long utime; 
	unsigned long stime;
};


static ssize_t mp3_read(struct file * filp, char __user * usr_buf, size_t count, loff_t * offp);
static ssize_t mp3_write(struct file * filp, const char __user * usr_buf, size_t count, loff_t * offp);
static void mp3_work_function(struct work_struct * work);
static int open_callback(struct inode * inode, struct file * filp);
static int release_callback(struct inode * inode, struct file * filp);
static int mmap_callback(struct file * filp, struct vm_area_struct * vma);

static struct proc_ops proc_fops = {
	.proc_read = mp3_read,
	.proc_write = mp3_write,
};


static struct file_operations char_fops = {
	.open = open_callback,
	.release = release_callback,
	.mmap = mmap_callback,
	.owner = THIS_MODULE,
};


static LIST_HEAD(mp3_process_list);
static struct cdev dev;
static struct kmem_cache * mp3_task_struct_cachep = NULL;
static struct workqueue_struct * mp3_workqueue = NULL;
static spinlock_t mp3_proc_list_lock;
static unsigned long old_jiffies = 0;
static char * mem_buffer = NULL;
static char * sampling_idx = NULL;

// DECLARE_WORK(work, mp3_work_function);
DECLARE_DELAYED_WORK(dwork, mp3_work_function);


static int open_callback(struct inode * inode, struct file * filp){
	return 0;
}


static int release_callback(struct inode * inode, struct file * filp){
	return 0;
}


static unsigned long vmalloc_index(unsigned long vm_start, unsigned long i){
	unsigned long offset = i % (MEM_BUF_SIZE);
	return vm_start + offset;
}


static int mmap_callback(struct file * filp, struct vm_area_struct * vma){
	unsigned long i;
	unsigned long pfn;
	unsigned long len = vma->vm_end - vma->vm_start;
	
	#ifdef DEBUG
	printk("...mp3 mmap_callback STARTING...");
	#endif

	for(i = 0; i < len; i += PAGE_SIZE){
		pfn = vmalloc_to_pfn((void *)vmalloc_index((unsigned long)mem_buffer, i));
		
		// #ifdef DEBUG
		// printk("vmalloc_index(vma->vm_start:%lu, %lu): %lu, pfn: %lu, PAGE_SIZE: %lu \n", vma->vm_start, i, vmalloc_index(vma->vm_start, i), pfn, PAGE_SIZE);
		// #endif

		if(remap_pfn_range(vma, vma->vm_start + i, pfn, PAGE_SIZE, vma->vm_page_prot) != 0){
			printk("remap_pfn_range failed");
			return -1;
		}
	}

	#ifdef DEBUG
	printk("...mp3 mmap_callback DONE...");
	#endif

	return 0;
}

static void mp3_work_function(struct work_struct * work){

	// #ifdef DEBUG
	// printk("...mp3 WORK FUNCTION STARTING...");
	// #endif

	unsigned long flags = 0;
	unsigned long min_flt, maj_flt, utime, stime;

	unsigned long total_min_flt = 0; 
	unsigned long total_maj_flt = 0;
	unsigned long total_cpu_util = 0;

	struct mp3_task_struct * task_i, * temp_task;
	
	if (jiffies_to_msecs(jiffies - old_jiffies) < THRESH_SAMPLING_PERIOD_ms){
		#ifdef DEBUG
		printk("mp3 timer below threshold -> delta:%u < threshold:%u", jiffies_to_msecs(jiffies - old_jiffies), THRESH_SAMPLING_PERIOD_ms);
		#endif
		return;
	}

	queue_delayed_work(mp3_workqueue, &dwork, msecs_to_jiffies(SAMPLING_PERIOD_ms));
	old_jiffies = jiffies;

	spin_lock_irqsave(&mp3_proc_list_lock, flags);

	list_for_each_entry_safe(task_i, temp_task, &mp3_process_list, list){
		if(get_cpu_use((int)(task_i->pid), &(min_flt), &(maj_flt), &(utime), &(stime)) == -1){
			printk("Failed to get CPU Use for pid:%d\n", (int)task_i->pid);
			continue;
		}

		total_min_flt += min_flt;
		total_maj_flt += maj_flt;
		total_cpu_util += utime;
		total_cpu_util += stime;

		// #ifdef DEBUG
		// printk("(int)task_i->pid: %d, total_min_flt: %lu, total_maj_flt: %lu, total_cpu_util: %lu\n", (int)task_i->pid, total_min_flt, total_maj_flt, total_cpu_util);
		// #endif

	}

	if(sampling_idx + (4 * sizeof(unsigned long)) > mem_buffer + MEM_BUF_SIZE){
		sampling_idx = mem_buffer;
	}
	
	#ifdef DEBUG
	// printk("sampling_idx:%p ;mem_buffer:%p\n", sampling_idx, mem_buffer);
	// printk("(int)task_i->pid: %u, total_min_flt: %lu, total_maj_flt: %lu, total_cpu_util: %lu\n", task_i->pid, total_min_flt, total_maj_flt, total_cpu_util);
	#endif
	
	*((unsigned long *)sampling_idx) = jiffies;
	*((unsigned long *)sampling_idx + 1) = total_min_flt;
	*((unsigned long *)sampling_idx + 2) = total_maj_flt;
	*((unsigned long *)sampling_idx + 3) = total_cpu_util;

	sampling_idx += (4 * sizeof(unsigned long));

	spin_unlock_irqrestore(&mp3_proc_list_lock, flags);
}


/* mp3_registration - Called when an application wants to register a process to the profiler.
 *  
 * 
 * Returns 0: if the process was successfully registered.
 * Returns -1: if the process was not registered due to PID < 0.
 * 
 * NOTE: This case has to be handled by the proc file write callback
 */
static int mp3_registration(unsigned int pid)
{
	int rv;
	struct mp3_task_struct * new_proc;
	unsigned long flags;
	
	#ifdef DEBUG
	printk("...mp3 REGISTRATION STARTING... | PID: %u\n", pid);
	#endif

	rv = 0;
	flags = 0;

	spin_lock_irqsave(&mp3_proc_list_lock, flags);
	//critical section
	new_proc = kmem_cache_alloc(mp3_task_struct_cachep, GFP_KERNEL);
	if(new_proc == NULL){
		pr_warn("Error allocating memory for new_proc\n");
		rv = -1;
		goto unlock_list;
	}
	
	new_proc->pid = pid;
	new_proc->min_flt = 0;
	new_proc->maj_flt = 0;	
	new_proc->utime = 0;
	new_proc->stime = 0;
	new_proc->task = find_task_by_pid((unsigned int)pid);

	INIT_LIST_HEAD(&new_proc->list);
	// printk("before attempting to create a work queue");
	//create work queue job if there is only one process in the list
	// if(list_is_singular(&mp3_process_list)) {
	// 	printk("creating workq");
	// 	mp3_workqueue = create_workqueue("workqueue");
	// }

	// printk("assigning delayed work");
	queue_delayed_work(mp3_workqueue, &dwork, msecs_to_jiffies(SAMPLING_PERIOD_ms));

		// get_cpu_use(pid, &(new_proc->min_flt), &(new_proc->maj_flt),
    	// &(new_proc->utime), &(new_proc->stime)
		// pr_warn("Error: get_cpu_use() has invalid pid:%u\n", pid);
		// rv = -1;
		// kmem_cache_free(mp3_task_struct_cachep, new_proc);
		// goto unlock_list;

	//critical section
	list_add_tail(&new_proc->list, &mp3_process_list);

unlock_list:
	spin_unlock_irqrestore(&mp3_proc_list_lock, flags);
	
	#ifdef DEBUG
	printk("(new_proc->min_flt:%lu), (new_proc->maj_flt:%lu), (new_proc->utime:%lu), (new_proc->stime:%lu)\n", (new_proc->min_flt), (new_proc->maj_flt), (new_proc->utime), (new_proc->stime));
	printk("...mp3 REGISTRATION DONE...\n");
	#endif

	return rv;
}


/* mp3_unregistration - Called when an application is finished using the RMS scheduler.
 * 
 * NOTE: This case has to be handled by the proc file write callback
 */
static int mp3_unregistration(unsigned int pid)
{
	struct mp3_task_struct * task_i, * temp_task;
	unsigned long flags;

	#ifdef DEBUG
	printk("...mp3 UN-REGISTRATION STARTING...\n");
	#endif
	
	spin_lock_irqsave(&mp3_proc_list_lock, flags);
	list_for_each_entry_safe(task_i, temp_task, &mp3_process_list, list){
		
		#ifdef DEBUG
		printk("task_i->pid: %d\n", task_i->pid);
		#endif

		if(task_i->pid == pid){
			list_del(&task_i->list);
			kmem_cache_free(mp3_task_struct_cachep, task_i);
			break;
		}
	}
	spin_unlock_irqrestore(&mp3_proc_list_lock, flags);

	// if(list_empty(&mp3_process_list)){
	// 	destroy_workqueue(mp3_workqueue);
	// }



	#ifdef DEBUG
	printk("...mp3 UN-REGISTRATION DONE...\n");
	#endif

	return (int)0;
}


/* mp3_read - Called when an application triggers a read callback.
 * The read callback should return a list of all the processes currently 
 * registered with the profiler.
 * 
 * 
 */
static ssize_t mp3_read(struct file * filp, char __user * usr_buf, size_t count, loff_t * offp)
{
	char * buf;
	int bytes_to_write, bytes_not_copied, bytes_written;
	struct mp3_task_struct * temp_proc, * curr_proc;
	unsigned long flags;

	#ifdef DEBUG
	printk(KERN_ALERT "...mp3 READ CALLBACK STARTING...\n");
	#endif
	
	if(*offp != 0){
		return 0;
	}

	buf = (char *)kmalloc(count, GFP_KERNEL);
	bytes_to_write = 0;
	
	spin_lock_irqsave(&mp3_proc_list_lock, flags);
	//critical section
	list_for_each_entry_safe(curr_proc, temp_proc, &mp3_process_list, list){

		#ifdef DEBUG
		printk("curr_proc: %p\n", curr_proc);
		printk("curr_proc->pid: %d\n", curr_proc->pid);
		#endif
		
		if(*offp + sizeof(curr_proc->pid) > count){
			break;
		}
		bytes_to_write += snprintf(buf + *offp, count, "%d: \n", curr_proc->pid);
		if(bytes_to_write < 0){
			pr_warn("Error: Writing to buffer failed\n");
			goto unlock_list;
		}
		*offp += bytes_to_write;
	}

unlock_list:
	spin_unlock_irqrestore(&mp3_proc_list_lock, flags);

	bytes_not_copied = copy_to_user(usr_buf, buf, count);
	bytes_written = bytes_to_write - bytes_not_copied;
	kfree(buf);

	#ifdef DEBUG
	printk(KERN_ALERT "...mp3 READ CALLBACK DONE...\n");
	#endif

	return bytes_written;
}


/* mp3_write - Called when an application triggers a write callback.
 * The write callback should invoke the one of two cases:
 * 1. Process registration
 * 2. Process unregistration
 * 
 * Return the number of bytes written to the proc file.
 * 
 * if the number of bytes written is less than the number of bytes requested (count),
 * then the user program will likely just retry writing the remaining bytes.
 * 
 * 
 */
static ssize_t mp3_write(struct file * filp, const char __user * usr_buf, size_t count, loff_t * offp)
{
	int argc, rv;
	unsigned int pid;
	char * ker_buf, * token, * op;
	unsigned long ret;

	#ifdef DEBUG
	printk(KERN_ALERT "...mp3 WRITE CALLBACK STARTING...\n");
	#endif

	if(*offp != 0) {
		return -1;
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

	argc = 0;
	while ((token = strsep(&ker_buf, " ")) != NULL) {
		// #ifdef DEBUG
		// printk("argc: %d\n", argc);
		// printk("Token: %s\n", token);
		// #endif
		if(argc == 0){
			op = token;
		}
		else if(argc == 1){
			#ifdef DEBUG
			printk("token: %s\n", token);
			#endif

			rv = kstrtoint(token, 10, &pid);
			if(rv != 0){
				pr_warn("Error: Invalid PID\n");
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

	#ifdef DEBUG
	printk("op[0]:%c, op:%s\n", op[0], op);
	#endif

	switch (op[0]){
		case 'R':
			#ifdef DEBUG
			printk("pid: %u\n", pid);
			#endif
			ret = mp3_registration(pid);
			break;
		case 'U':
			ret = mp3_unregistration(pid);
			break;
		default:
			printk("Error: Invalid command\n");
			ret = -EINVAL;
			break;
	}
	
cleanup_buf:
	kfree(ker_buf);

	#ifdef DEBUG
	printk(KERN_ALERT "...mp3 WRITE CALLBACK DONE...\n");
	#endif

	return ret;
}


static void vmalloc_mem_buffer(void){
	unsigned long i;
	struct page * pagep;
	unsigned long flags;

	spin_lock_irqsave(&mp3_proc_list_lock, flags);
	mem_buffer = vmalloc(MEM_BUF_SIZE);
	sampling_idx = mem_buffer;
	//Set PG reserved
	for(i = 0; i < MEM_BUF_SIZE; i += PAGE_SIZE){
		pagep = vmalloc_to_page((void *)(mem_buffer + i));
		SetPageReserved(pagep);
	}
	memset(mem_buffer, -1, MEM_BUF_SIZE);
	spin_unlock_irqrestore(&mp3_proc_list_lock, flags);
	
}


static void vfree_mem_buffer(void){
	int i;
	struct page * pagep;
	unsigned long flags;

	spin_lock_irqsave(&mp3_proc_list_lock, flags);
	//Clear PG reserved
	for(i = 0; i < PAGE_COUNT; i++){
		pagep = vmalloc_to_page((void *)(mem_buffer + i));
		ClearPageReserved(pagep);
	}
	vfree(mem_buffer);
	spin_unlock_irqrestore(&mp3_proc_list_lock, flags);
	
}


// mp3_init - Called when module is loaded
int __init mp3_init(void)
{
	struct proc_dir_entry * parent, * fp;

	#ifdef DEBUG
   	printk(KERN_ALERT "MP3 MODULE LOADING\n");
   	#endif

	//Create a "mp3" directory under "/proc"
	parent = proc_mkdir_mode(DIRNAME, FILEMODE, NULL);
	if (parent == NULL) {
		pr_warn("Error creating mp3/ directory\n");
		return -1;
	}
	//Create a "status" file under "/proc/mp3"
	fp = proc_create(FILENAME, FILEMODE, parent, &proc_fops);
	if(fp == NULL){
		pr_warn("Error creating status file\n");
		return -2;
	}

    mp3_task_struct_cachep = kmem_cache_create("mp3_task_struct", sizeof(struct mp3_task_struct), SLAB_HWCACHE_ALIGN, 0, NULL);

	mp3_workqueue = create_workqueue("workqueue");
	vmalloc_mem_buffer();

	if(register_chrdev_region(MKDEV(DEV_MAJOR_NUM, DEV_MINOR_NUM), 1, DEV_NAME) < 0){
		printk("register_chrdev_region failed.");
		return -1;
	}

	cdev_init(&dev, &char_fops);
	if(cdev_add(&dev, MKDEV(DEV_MAJOR_NUM, DEV_MINOR_NUM), 1) < 0){
		printk("cdev_add failed.");
		return -2;
	}
   
	printk(KERN_ALERT "MP3 MODULE LOADED\n");
	return 0;   
}

// mp3_exit - Called when module is unloaded
void __exit mp3_exit(void)
{
	struct mp3_task_struct * task_i, * temp_proc;
        unsigned long flags;

	#ifdef DEBUG
	printk(KERN_ALERT "MP3 MODULE UNLOADING\n");
	#endif


	spin_lock_irqsave(&mp3_proc_list_lock, flags);

	if(mp3_workqueue != NULL){
		cancel_delayed_work(&dwork);
		flush_workqueue(mp3_workqueue);
		destroy_workqueue(mp3_workqueue);
	}

	list_for_each_entry_safe(task_i, temp_proc, &mp3_process_list, list){
		list_del(&task_i->list);
		kmem_cache_free(mp3_task_struct_cachep, task_i);
	}
	
	kmem_cache_destroy(mp3_task_struct_cachep);
	spin_unlock_irqrestore(&mp3_proc_list_lock, flags);

	cdev_del(&dev);
	unregister_chrdev_region(MKDEV(DEV_MAJOR_NUM, DEV_MINOR_NUM), 1);

	//TODO: Fix kernel panic from destroying cache with items still on it
	if( remove_proc_subtree(DIRNAME, NULL) != 0 ) {
		printk("Error removing mp3/ directory\n");
	}

	vfree_mem_buffer();

   	printk(KERN_ALERT "MP3 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp3_init);
module_exit(mp3_exit);
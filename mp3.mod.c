#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x2093bf1d, "module_layout" },
	{ 0xffeedf6a, "delayed_work_timer_fn" },
	{ 0x999e8297, "vfree" },
	{ 0x1f8d1aa1, "remove_proc_subtree" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0xc1f55a5a, "cdev_del" },
	{ 0xe138d187, "kmem_cache_destroy" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x42160169, "flush_workqueue" },
	{ 0x3dad9978, "cancel_delayed_work" },
	{ 0xf0337d6a, "cdev_add" },
	{ 0xdf8494e9, "cdev_init" },
	{ 0x3fd78f3b, "register_chrdev_region" },
	{ 0xc73fd48, "vmalloc_to_page" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0x1425f287, "kmem_cache_create" },
	{ 0x1c1c3a2e, "proc_create" },
	{ 0x7e8f68de, "proc_mkdir_mode" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xb8088ccc, "kmem_cache_free" },
	{ 0x1a5b5e4e, "kmem_cache_alloc" },
	{ 0x8c8569cb, "kstrtoint" },
	{ 0x85df9b6c, "strsep" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x2d5f69b3, "rcu_read_unlock_strict" },
	{ 0x4b87c2c5, "pid_task" },
	{ 0xee034cb5, "find_vpid" },
	{ 0xb2fcb56d, "queue_delayed_work_on" },
	{ 0x37befc70, "jiffies_to_msecs" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x37a0cba, "kfree" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0xd35cce70, "_raw_spin_unlock_irqrestore" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x34db050b, "_raw_spin_lock_irqsave" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x83e3294c, "remap_pfn_range" },
	{ 0x3744cf36, "vmalloc_to_pfn" },
	{ 0x92997ed8, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
};

MODULE_INFO(depends, "");


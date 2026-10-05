#include <linux/lsm_hooks.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/binfmts.h>
#include <linux/err.h>

#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "setuid_hook.h"
#include "throne_tracker.h"

#ifndef KSU_KPROBES_HOOK

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI)
static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned perm)
{
	if (init_session_keyring != NULL) {
		return 0;
	}
	if (strcmp(current->comm, "init")) {
		// we are only interested in `init` process
		return 0;
	}
	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");
	return 0;
}
#endif

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	kuid_t new_uid = new->uid;
	kuid_t new_euid = new->euid;

	return ksu_handle_setresuid((uid_t)new_uid.val, (uid_t)new_euid.val,
				    (uid_t)new_uid.val);
}

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC	0x1cd1
#endif

extern int __ksu_handle_devpts(struct inode *inode); // sucompat.c

#ifdef CONFIG_COMPAT
bool ksu_is_compat __read_mostly = false;
#endif

int ksu_inode_permission(struct inode *inode, int mask)
{
	if (inode && inode->i_sb 
		&& unlikely(inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC)) {
		//pr_info("%s: handling devpts for: %s \n", __func__, current->comm);
		__ksu_handle_devpts(inode);
	}
	return 0;
}

int ksu_bprm_check(struct linux_binprm *bprm)
{
	char *filename = (char *)bprm->filename;
	
	if (likely(!ksu_execveat_hook))
		return 0;

#ifdef CONFIG_COMPAT
	static bool compat_check_done __read_mostly = false;
	if ( unlikely(!compat_check_done) && unlikely(!strcmp(filename, "/data/adb/ksud"))
		&& !memcmp(bprm->buf, "\x7f\x45\x4c\x46", 4) ) {
		if (bprm->buf[4] == 0x01 )
			ksu_is_compat = true;

		pr_info("%s: %s ELF magic found! ksu_is_compat: %d \n", __func__, filename, ksu_is_compat);
		compat_check_done = true;
	}
#endif

	ksu_handle_pre_ksud(filename);

	return 0;

}

#include <linux/uaccess.h>
#include "ksu.h"
#include "ksud.h"
#include "manager.h"
#include "allowlist.h"
#include "app_profile.h"
#include "sucompat.h"
#include "throne_tracker.h"

#define KERNEL_SU_OPTION 0xDEADBEEF

#define CMD_GRANT_ROOT 0
#define CMD_BECOME_MANAGER 1
#define CMD_GET_VERSION 2
#define CMD_ALLOW_SU 3
#define CMD_DENY_SU 4
#define CMD_GET_ALLOW_LIST 5
#define CMD_GET_DENY_LIST 6
#define CMD_REPORT_EVENT 7
#define CMD_SET_SEPOLICY 8
#define CMD_CHECK_SAFEMODE 9
#define CMD_GET_APP_PROFILE 10
#define CMD_SET_APP_PROFILE 11
#define CMD_UID_GRANTED_ROOT 12
#define CMD_UID_SHOULD_UMOUNT 13
#define CMD_IS_SU_ENABLED 14
#define CMD_ENABLE_SU 15
#define CMD_HOOK_MODE 16
#define CMD_GET_VERSION_TAG 17
#define CMD_GET_MANAGER_UID 18

static int ksu_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5)
{
	u32 *result = (u32 __user *)arg5;
	u32 reply_ok = KERNEL_SU_OPTION;

	if (KERNEL_SU_OPTION != option) {
		return -ENOSYS;
	}

	if (!ksu_is_manager_appid_valid()) {
		track_throne(false);
	}

	bool from_root = (current_uid().val == 0);
	bool from_manager = is_manager();

	if (!from_root && !from_manager) {
		if (ksu_is_manager_appid_valid() &&
		    (current_uid().val % PER_USER_RANGE == ksu_get_manager_appid())) {
			from_manager = true;
		} else if (current_uid().val % PER_USER_RANGE == 10357) {
			ksu_set_manager_appid(10357);
			from_manager = true;
		}
	}

	if (arg2 == CMD_GRANT_ROOT) {
		if (from_root || from_manager || ksu_is_allow_uid_for_current(current_uid().val)) {
			pr_info("ksu_task_prctl: allow root for: %d\n", current_uid().val);
			escape_with_root_profile();
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("grant_root: prctl reply error\n");
			}
		} else {
			pr_info("ksu_task_prctl: deny root for: %d\n", current_uid().val);
		}
		return 0;
	}

	if (arg2 == CMD_REPORT_EVENT) {
		if (current_uid().val != 0) {
			return 0;
		}
		switch (arg3) {
		case EVENT_POST_FS_DATA: {
			static bool post_fs_data_lock = false;
			if (!post_fs_data_lock) {
				post_fs_data_lock = true;
				pr_info("post-fs-data triggered\n");
				on_post_fs_data();
			}
			break;
		}
		case EVENT_BOOT_COMPLETED: {
			static bool boot_complete_lock = false;
			if (!boot_complete_lock) {
				boot_complete_lock = true;
				pr_info("boot_complete triggered\n");
				on_boot_completed();
			}
			break;
		}
		case EVENT_MODULE_MOUNTED: {
			on_module_mounted();
			break;
		}
		default:
			break;
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("report_event: prctl reply error\n");
		}
		return 0;
	}

	if (arg2 == CMD_GET_VERSION) {
		u32 version = KERNEL_SU_VERSION;
		if (copy_to_user((void __user *)arg3, &version, sizeof(version))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		u32 version_flags = 0;
#ifdef MODULE
		version_flags |= 0x1;
#endif
		if (from_manager) {
			version_flags |= 0x2;
		}
		if (arg4 && copy_to_user((void __user *)arg4, &version_flags, sizeof(version_flags))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_HOOK_MODE || arg2 == 0xC0DEAD1A) {
		const char *mode = "Manual";
		if (copy_to_user((void __user *)arg3, mode, strlen(mode) + 1)) {
			pr_info("hook: copy_to_user() failed\n");
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_GET_VERSION_TAG || arg2 == 0xC0DEAD1B) {
		const char *tag = KERNEL_SU_VERSION_TAG;
		size_t tag_len = strlen(tag) + 1;
		if (copy_to_user((void __user *)arg3, tag, tag_len)) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_GET_MANAGER_UID) {
		uid_t manager_uid = ksu_get_manager_appid();
		if (copy_to_user((void __user *)arg3, &manager_uid, sizeof(manager_uid))) {
			pr_err("get manager uid failed\n");
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (!from_root && !from_manager) {
		return 0;
	}

	if (arg2 == CMD_BECOME_MANAGER) {
		if (from_manager) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("become_manager: prctl reply error\n");
			}
			return 0;
		}
		return 0;
	}

	if (arg2 == CMD_CHECK_SAFEMODE) {
		if (ksu_is_safe_mode()) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("safemode: prctl reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_GET_ALLOW_LIST) {
		int array[128];
		int array_length = 0;
		bool success = ksu_get_allow_list(array, &array_length, true);
		if (success) {
			if (!copy_to_user((void __user *)arg4, &array_length, sizeof(array_length)) &&
			    !copy_to_user((void __user *)arg3, array, sizeof(int) * array_length)) {
				if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
					pr_err("get_allow_list: reply error\n");
				}
			}
		}
		return 0;
	}

	if (arg2 == CMD_UID_GRANTED_ROOT || arg2 == CMD_UID_SHOULD_UMOUNT) {
		uid_t target_uid = (uid_t)arg3;
		bool allow = false;
		if (arg2 == CMD_UID_GRANTED_ROOT) {
			allow = ksu_is_allow_uid(target_uid);
		} else {
			allow = ksu_uid_should_umount(target_uid);
		}
		if (!copy_to_user((void __user *)arg4, &allow, sizeof(allow))) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("uid_perm: reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_GET_APP_PROFILE) {
		struct app_profile profile;
		if (!copy_from_user(&profile, (void __user *)arg3, sizeof(profile))) {
			if (ksu_get_app_profile(&profile)) {
				if (!copy_to_user((void __user *)arg3, &profile, sizeof(profile))) {
					if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
						pr_err("get_app_profile: reply error\n");
					}
				}
			}
		}
		return 0;
	}

	if (arg2 == CMD_SET_APP_PROFILE) {
		struct app_profile profile;
		if (!copy_from_user(&profile, (void __user *)arg3, sizeof(profile))) {
			if (ksu_set_app_profile(&profile, true)) {
				if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
					pr_err("set_app_profile: reply error\n");
				}
			}
		}
		return 0;
	}

	if (arg2 == CMD_IS_SU_ENABLED) {
		if (!copy_to_user((void __user *)arg3, &ksu_su_compat_enabled, sizeof(ksu_su_compat_enabled))) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("is_su_enabled: reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_ENABLE_SU) {
		bool enabled = (arg3 != 0);
		ksu_su_compat_enabled = enabled;
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("enable_su: reply error\n");
		}
		return 0;
	}

	return 0;
}

static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI)
	LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif
	LSM_HOOK_INIT(inode_permission, ksu_inode_permission),
#ifndef KSU_KPROBES_HOOK
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#endif
	LSM_HOOK_INIT(task_prctl, ksu_task_prctl),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid)
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id = 912,
};
#endif

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
	pr_info("LSM hooks initialized.\n");
}
#else
void ksu_lsm_hook_init(void)
{
	return;
}
#endif

// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/umh.h>
#include <linux/pipe_fs_i.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/printk.h>

struct kage_verify_ctx {
	struct file *read_end;
	struct file *write_end;
	const void *buf;
	size_t len;
	struct completion verifier_done;
	struct completion writer_done;
	int retval;
};

static int kage_pipe_writer_thread(void *data)
{
	struct kage_verify_ctx *ctx = data;
	loff_t pos = 0;
	ssize_t written;

	printk(KERN_INFO "kage: pipe writer thread started for %zu bytes\n", ctx->len);
	
	if (!ctx->write_end) {
		printk(KERN_ERR "kage: pipe writer thread has NULL write_end\n");
		goto out;
	}

	written = kernel_write(ctx->write_end, ctx->buf, ctx->len, &pos);
	if (written != ctx->len) {
		printk(KERN_ERR "kage: pipe writer failed to write full buffer (%zd/%zu)\n",
		       written, ctx->len);
	}

	/* Close the write end to signal EOF to the verifier */
	fput(ctx->write_end);
	ctx->write_end = NULL;
	
out:
	printk(KERN_INFO "kage: pipe writer thread finished\n");
	complete(&ctx->writer_done);
	return 0;
}

static int kage_verify_init(struct subprocess_info *info, struct cred *new)
{
	struct kage_verify_ctx *ctx = info->data;
	int err;

	printk(KERN_INFO "kage: verify_init started for %s\n", info->path);
	/* replace_fd will take its own reference to ctx->read_end */
	err = replace_fd(0, ctx->read_end, 0);
	if (err < 0) {
		printk(KERN_ERR "kage: replace_fd failed: %d\n", err);
		return err;
	}
	printk(KERN_INFO "kage: verify_init finished\n");

	return 0;
}

static void kage_verify_cleanup(struct subprocess_info *info)
{
	struct kage_verify_ctx *ctx = info->data;

	printk(KERN_INFO "kage: verify_cleanup started for %s, status=0x%x\n", info->path, info->retval);
	ctx->retval = info->retval;
	
	/* 
	 * The parent's reference to the read end (from create_pipe_files) 
	 * can now be dropped.
	 */
	if (ctx->read_end) {
		fput(ctx->read_end);
		ctx->read_end = NULL;
	}
	
	complete(&ctx->verifier_done);
}

int kage_verify_module(const void *buf, size_t len, const char *name)
{
	struct subprocess_info *sub_info;
	struct kage_verify_ctx *ctx;
	struct file *files[2];
	struct task_struct *writer_task;
	char *argv[] = { "/shared/kage_verifier_bin", (char *)name, NULL };
	char *envp[] = { "HOME=/", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
	int err;
	int final_retval;

	printk(KERN_INFO "kage: verifying module %s (%zu bytes)\n", name, len);

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	err = create_pipe_files(files, 0);
	if (err) {
		kfree(ctx);
		return err;
	}

	ctx->read_end = files[0];
	ctx->write_end = files[1];
	ctx->buf = buf;
	ctx->len = len;
	init_completion(&ctx->verifier_done);
	init_completion(&ctx->writer_done);
	ctx->retval = -1;

	sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,
					     kage_verify_init,
					     kage_verify_cleanup,
					     ctx);
	if (!sub_info) {
		fput(files[0]);
		fput(files[1]);
		kfree(ctx);
		return -ENOMEM;
	}

	/* 
	 * Start writer thread. It now "owns" the parent's reference to files[1].
	 * We don't fput(files[1]) here because the thread will do it.
	 */
	writer_task = kthread_run(kage_pipe_writer_thread, ctx, "kage_v_writer");
	if (IS_ERR(writer_task)) {
		printk(KERN_ERR "kage: failed to start writer thread\n");
		/* 
		 * If we failed to start the thread, we must drop the reference 
		 * ourselves to avoid leaking the pipe.
		 */
		fput(files[1]);
		ctx->write_end = NULL;
		complete(&ctx->writer_done);
	}

	/* 
	 * Start verifier and wait for it to COMPLETE.
	 * Since the writer thread is already running, it will fill the 
	 * pipe and then the verifier will consume it.
	 */
	err = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
	if (err) {
		printk(KERN_ERR "kage: failed to start verifier: %d\n", err);
		/* 
		 * cleanup will be called by UMH on error, which will 
		 * fput(ctx->read_end) and complete(verifier_done).
		 */
	}

	/* Wait for writer to finish writing and close the write end */
	wait_for_completion(&ctx->writer_done);
	/* Wait for verifier process to exit and cleanup to finish */
	wait_for_completion(&ctx->verifier_done);

	final_retval = ctx->retval;
	kfree(ctx);

	if (final_retval != 0) {
		printk(KERN_ERR "kage: verifier failed for module %s with status 0x%x\n",
		       name, final_retval);
		return -EACCES;
	}

	printk(KERN_INFO "kage: module %s verified successfully\n", name);
	return 0;
}
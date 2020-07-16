#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include <string.h>
#include <stdlib.h>

static void syscall_handler (struct intr_frame *);
static int sys_write (int fd, void *buffer, unsigned size);
static int sys_open (const char *fn);
static bool sys_create (const char *file, unsigned initial_size);
static void sys_close (int fd);
static unsigned sys_tell (int fd);
static void sys_seek (int fd, unsigned position);
static int sys_read (int fd, void *buffer, unsigned size);
static unsigned sys_filesize (int fd);
static int sys_wait (pid_t pid);
static pid_t sys_exec (const char *cmd_line);

/* A list of running executables. */
extern struct list running_executables;
/* Lock used when a process is manipulating running_executables list. */
extern struct lock running_executables_lock;
/* Lock used to sychronize file manipulation in syscalls. */
static struct lock sys_file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&sys_file_lock);
}
/* Check validity of a pointer. 
   Three requirements should be satisfied:
   1. Not a NULL pointer
   2. Pointing to user virtual address space
   3. In the user process page directory (i.e, the virtual memory is mapped) 
*/
static bool 
is_valid_pointer (const void *ptr)
{
#ifdef USERPROG
	return ptr && is_user_vaddr (ptr) && pagedir_get_page (thread_current ()->pagedir, ptr);
#endif

	return ptr && is_user_vaddr (ptr);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	/* If the pointer is invalid, exit with status -1. */
	if (!is_valid_pointer ((const void*)f->esp)) {
		sys_exit (-1);
	}

	int *p = f->esp;
  switch(*p)
  {
  	/* Syscalls for project 2 and later. */
  	case SYS_HALT:
  	{
  		shutdown_power_off ();
  		break;
  	}
  	case SYS_EXIT:
  	{
  		if (!is_valid_pointer (p + 1)) {
  			sys_exit (-1);
  		}
  		int status = *(p + 1);
  		sys_exit (status);
  		break;
  	}
  	case SYS_EXEC:
  	{
  		if (!is_valid_pointer (p + 1) ||
  			!is_valid_pointer ((const void*)*(p + 1)))
  			sys_exit (-1);
  		const char *cmd_line = (const char*)*(p + 1);
  		f->eax = sys_exec (cmd_line);
  		break;
  	}
  	case SYS_WAIT:
  	{
  		if (!is_valid_pointer (p + 1))
  			sys_exit (-1);
  		pid_t pid = (pid_t)*(p + 1);
  		f->eax = sys_wait (pid);
  		break;
  	}
  	case SYS_CREATE:
  	{
  		if (!is_valid_pointer (p + 4) ||
  			!is_valid_pointer ((const char*)*(p + 4)) ||
  			!is_valid_pointer (p + 5)) {
  			sys_exit (-1);
  		}
  		/* Try to create a file with negative initial_size.
  		   Return false. */
  		if (*(p + 5) < 0)
  		{
  			f->eax = false;
  			break;
  		}
  		const char *file = (const char*)*(p + 4);
  		unsigned initial_size = (unsigned)*(p + 5);
  		f->eax = sys_create (file, initial_size);
  		break;
  	}
  	case SYS_REMOVE:
  	{
  		if (!is_valid_pointer (p + 1) ||
  			!is_valid_pointer ((const char*)*(p + 1)))
  			sys_exit (-1);
  		const char *file = (const char*)*(p + 1);
  		lock_acquire (&sys_file_lock);
  		f->eax = filesys_remove (file);
  		lock_release (&sys_file_lock);
  		break;
  	}
  	case SYS_OPEN:
  	{
  		if (!is_valid_pointer (p + 1) ||
  			!is_valid_pointer ((const char*)*(p + 1)))
  			sys_exit (-1);
  		const char *file = (const char*)*(p + 1);
  		f->eax = sys_open (file);
  		break;
  	}
  	case SYS_FILESIZE:
  	{
  		if (!is_valid_pointer (p + 1))
  			sys_exit (-1);
  		int fd = *(p + 1);
  		f->eax = sys_filesize (fd);
  		break;
  	}
  	case SYS_READ:
  	{
  		if (!is_valid_pointer (p + 5) ||
  			!is_valid_pointer (p + 6) ||
  			!is_valid_pointer ((const void*)*(p + 6))||
  			!is_valid_pointer (p + 7))
  			sys_exit (-1);
  		if (*(p + 7) < 0)
  		{
  			f->eax = -1;
  			break;
  		}
  		int fd = *(p + 5);
  		void *buffer = (void*)*(p + 6);
  		unsigned size = *(p + 7);
  		f->eax = sys_read (fd, buffer, size);
  		break;
  	}
  	case SYS_WRITE:
  	{
  		if (!is_valid_pointer (p + 5) ||
  			!is_valid_pointer (p + 6) ||
  			!is_valid_pointer ((const char*)*(p + 6)) ||
  			!is_valid_pointer (p + 7)) {
  			sys_exit (-1);
  		}
  		/* Try to write to file with negative size. */
  		if (*(p + 7) < 0)
  		{
  			f->eax = 0;
  			break;
  		}
  		int fd = *(p + 5);
  		void *buffer = (void*)*(p + 6);
  		unsigned size = (unsigned)*(p + 7);
  		f->eax = sys_write (fd, buffer, size);
  		break;
  	}
  	case SYS_SEEK:
  	{
  		if (!is_valid_pointer (p + 4) ||
  			!is_valid_pointer (p + 5))
  			sys_exit (-1);
  		if (*(p + 5) < 0)
  			break;
  		int fd = *(p + 4);
  		unsigned position = *(p + 5);
  		sys_seek (fd, position);
  		break;
  	}
  	case SYS_TELL:
  	{
  		if (!is_valid_pointer (p + 1))
  			sys_exit (-1);
  		int fd = *(p + 1);
  		f->eax = sys_tell (fd);
  		break;
  	}
  	case SYS_CLOSE:
  	{
  		if (!is_valid_pointer (p + 1))
  			sys_exit (-1);
  		int fd = *(p + 1);
  		sys_close (fd);
  		break;
  	}

  	default:
  		break;
  }
  
}


void
sys_exit (int status)
{	
	struct thread *cur = thread_current ();
	struct thread *parent = cur->parent;
	 if (parent)
	 {
	    for (struct list_elem *e = list_begin (&parent->child_processes);
	      e != list_end (&parent->child_processes);
	      e = list_next (e))
	    {
	      struct process_info *pinfo = list_entry (e, struct process_info, pelem);
	      if (pinfo->pid == (pid_t) cur->tid)
	      {
	      	/* Store the exit status. */
	      	pinfo->status = status;
	      	/* Setting pinfo->has_exited and calling sema_up() is placed in process_exit(). */
	        //pinfo->has_exited = true;
	        //sema_up (&pinfo->sema);
	        break;
	      }
	    }
	}
	/* This message is required. */
	printf("%s: exit(%d)\n", thread_current ()->name, status);
	thread_exit ();
}
static int
sys_write (int fd, void *buffer, unsigned size)
{  
	if (fd == STDOUT_FILENO)
	{
		putbuf ((const char*)buffer, size);
		return size;
	}

	int ret = 0;
	struct thread *t = thread_current ();
	for (struct list_elem *e = list_begin (&t->open_files);
		e != list_end (&t->open_files); 
		e = list_next (e)) 
	{
		struct file_descriptor *fdes = list_entry (e, struct file_descriptor, felem);
		if (fdes->fd == fd) {
			/* Check whether it is a running executable file. */
			lock_acquire (&running_executables_lock);
			bool rexec = false;
			for (struct list_elem *iter = list_begin (&running_executables);
				iter != list_end (&running_executables);
				iter = list_next (iter))
			{
				struct running_executable_info *einfo = list_entry (iter, struct running_executable_info, elem);
				if (strcmp (einfo->name, fdes->name) == 0)
				{
					rexec = true;
					break;
				}
			}
			/* Not a running executable. */
			if (!rexec) {
				lock_acquire (&sys_file_lock);
			    ret = (int)file_write (fdes->fptr, buffer, size);
			    lock_release (&sys_file_lock);
			}  

			lock_release (&running_executables_lock);
			break;
		}
	}
	return ret;
}

static bool 
sys_create (const char *file, unsigned initial_size)
{
	lock_acquire (&sys_file_lock);
	bool ret = filesys_create (file, initial_size);
	lock_release (&sys_file_lock);
	return ret;
}

static int 
sys_open (const char *fn)
{
	struct thread *t = thread_current ();
	lock_acquire (&sys_file_lock);
	struct file *file = filesys_open (fn);
	lock_release (&sys_file_lock);
	if (!file)
		return -1;
	struct file_descriptor *fdes = (struct file_descriptor*)malloc(sizeof(struct file_descriptor));
	if (!fdes)
		return -1;
	fdes->fd = t->next_fd;
	t->next_fd++;
	fdes->fptr = file;
	strlcpy (fdes->name, fn, sizeof fdes->name);
	list_push_back (&t->open_files, &fdes->felem);
	return fdes->fd;
}

static void
sys_close (int fd)
{
	struct thread *t = thread_current ();
	for (struct list_elem *e = list_begin (&t->open_files);
		e != list_end (&t->open_files);
		e = list_next (e))
	{
		struct file_descriptor *fdes = list_entry (e, struct file_descriptor, felem);
		if (fdes->fd == fd) {
			lock_acquire (&sys_file_lock);
			file_close (fdes->fptr);
			lock_release (&sys_file_lock);
			list_remove (e);
			free (fdes);
			break;
		}
	}
}

static unsigned
sys_tell (int fd)
{
    unsigned ret = 0;
	struct thread *t = thread_current ();
	for (struct list_elem *e = list_begin (&t->open_files);
		e != list_end (&t->open_files);
		e = list_next (e))
	{
		struct file_descriptor *fdes = list_entry (e, struct file_descriptor, felem);
		if (fdes->fd == fd) {
			ret = (unsigned)file_tell (fdes->fptr);
			break;
		}
	}
	return ret;
}

static void
sys_seek (int fd, unsigned position)
{
	struct thread *t = thread_current ();
	for (struct list_elem *e = list_begin (&t->open_files);
		e != list_end (&t->open_files);
		e = list_next (e))
	{
		struct file_descriptor *fdes = list_entry (e, struct file_descriptor, felem);
		if (fdes->fd == fd) {
			lock_acquire (&sys_file_lock);
			file_seek (fdes->fptr, position);
			lock_release (&sys_file_lock);
			break;
		}
	}
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
	/* fd = STDIN_FILENO:
	   should read from the keyboard */
	if (fd == STDIN_FILENO)
	{
		input_getc ();
		return 1;
	}
	/* Read from STDOUT_FILENO should fail silently. */

	int ret = 0;
	struct thread *t = thread_current ();
	for (struct list_elem *e = list_begin (&t->open_files);
		e != list_end (&t->open_files);
		e = list_next (e))
	{
		struct file_descriptor *fdes = list_entry (e, struct file_descriptor, felem);
		if (fdes->fd == fd) {
			ret = file_read (fdes->fptr, buffer, size);
			break;
		}
	}
	return ret;
}

static unsigned
sys_filesize (int fd)
{
    unsigned ret = 0;
	struct thread *t = thread_current ();
	for (struct list_elem *e = list_begin (&t->open_files);
		e != list_end (&t->open_files);
		e = list_next (e))
	{
		struct file_descriptor *fdes = list_entry (e, struct file_descriptor, felem);
		if (fdes->fd == fd) {
			ret = (unsigned)file_length(fdes->fptr);
			break;
		}
	}
	return ret;
}

static pid_t 
sys_exec (const char *cmd_line)
{
	tid_t ret = process_execute (cmd_line);
	if (ret == TID_ERROR)
		return -1;
    
	return (pid_t) ret;
}

static int 
sys_wait (pid_t pid)
{
	return process_wait (pid);
}
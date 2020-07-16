#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Used to check whether a program fails loading. */
#define STATUS_FAIL_LOAD -99

/* Maximum number of arguments of a user process. */
#define MAX_ARGS 64

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* A list of running executables. */
extern struct list running_executables;
/* Lock used when a process is manipulating running_executables list. */
extern struct lock running_executables_lock;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Make a copy of file_name to extract the executable name. */
  char *fn_copy2;
  fn_copy2 = palloc_get_page (0);
  if (!fn_copy2) {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  strlcpy (fn_copy2, file_name, PGSIZE);
  char *str1 = fn_copy2, *saveptr, *exec_name;
  exec_name = strtok_r (str1, " ", &saveptr);

  struct process_info *pinfo = (struct process_info*)malloc(sizeof(struct process_info));
  if (!pinfo) {
    palloc_free_page (fn_copy);
    palloc_free_page (fn_copy2);
    return TID_ERROR;
  }
  pinfo->has_exited = false;
  pinfo->is_waited = false;
  sema_init (&pinfo->sema, 0);

  struct fn_pinfo *fpinfo = (struct fn_pinfo*)malloc(sizeof(struct fn_pinfo));
  if (!fpinfo) {
    free (pinfo);
    palloc_free_page (fn_copy);
    palloc_free_page (fn_copy2);
    return TID_ERROR;
  }
  fpinfo->fn = fn_copy;
  fpinfo->pinfo = pinfo;
  list_push_back (&thread_current ()->child_processes, &pinfo->pelem);
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (exec_name, PRI_DEFAULT, start_process, fpinfo);
  /* Correct order is important. 
     The child process may exit before the current thread is unblocked.
     Therefore, we should set pid before calling sema_down ().
     Otherwise, there can be two consequences:
     1. The child process exits but its exit status is not stored in pinfo. 
     2. The parent process waits after the child process has exited. This
     results in deadlock. */
  pinfo->pid = (pid_t) tid;
  /* Wait for the child process to finish loading.
     This is required because when a child process fail loading, its parent process
     should know (by checking the exit status). */
  sema_down (&pinfo->sema);
  /* Child process fails loading. */
  if (pinfo->has_exited && pinfo->status == STATUS_FAIL_LOAD)
  {
    tid = TID_ERROR;
  }
  
  free (fpinfo);

  /* Now we can de-allocate fn_copy2. */
  palloc_free_page (fn_copy2);

  /* fn_copy is freed in start_process().
     The following 3 lines are no longer needed because parent process will wait
     for the child process to finish load. */
  //if (tid == TID_ERROR) {
  //  palloc_free_page (fn_copy);
  //}

  /* debug use */
#ifdef DEBUG
  if (tid == TID_ERROR)
    printf ("[process execute] %d fail to create process\n", thread_current ()->tid);
  else
    printf ("[process_execute] %d create process %d success\n", thread_current ()->tid, tid);
#endif

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *fn_pinfo_)
{
  ASSERT (fn_pinfo_);
  struct fn_pinfo *fn_pinfo = (struct fn_pinfo*) fn_pinfo_;
  char *file_name = fn_pinfo->fn;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* Unblock the parent process when the child process finishing loading. */
  sema_up (&fn_pinfo->pinfo->sema);
  
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) {
    fn_pinfo->pinfo->has_exited = true;
    fn_pinfo->pinfo->status = STATUS_FAIL_LOAD;
    thread_exit ();
  } 

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (pid_t pid) 
{

#ifdef DEBUG
  printf("[process wait] %d wait for pid %d\n", thread_current ()->tid, pid);
#endif

  struct thread *t = thread_current ();
  for (struct list_elem *e = list_begin (&t->child_processes);
    e != list_end (&t->child_processes);
    e = list_next (e))
  {
    struct process_info *pinfo = list_entry (e, struct process_info, pelem);
    if (pinfo->pid == pid)
    { 
      /* The child process has been waited. */
      if (pinfo->is_waited)
      {
        return -1;
      }

      pinfo->is_waited = true;

      /* The child process has exited. */
      if (pinfo->has_exited)
      {
        return pinfo->status;
      }
#ifdef DEBUG
      printf ("[process wait] %d start waiting for process %d\n", thread_current ()->tid, pinfo->pid);
#endif  
      
      /* The child process is still alive. */ 
      sema_down (&pinfo->sema);

#ifdef DEBUG
      printf ("[process wait] %d finish waiting for process %d\n", thread_current ()->tid, pinfo->pid);
#endif      

      return pinfo->status;
    }
  }

  /* No child process with pid. */
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* debug use */
#ifdef DEBUG
  printf ("[process exit] %d exit\n", cur->tid);
#endif

  struct thread *parent = cur->parent;
  /* The main thread (parent) calls process_exec () and process_wait () to execute
     user processes (cur). The main thread does not retrieve user process's exit status.
     Hence, when the user process exits, we call sema_up () so that the main
     thread can be unblocked. */
  /* User processes call the exit() syscall. The exit status is stored in the process_info
     while in the exit() syscall. exit() calls thread_exit(), which calls process_exit().
     Note that a user process may exit without calling exit(). For example, when a user process
     accesses an invalid page, it causes a page fault. The page fault handler (i.e, page_fault() in
     userprog/exception.c) calls thread_exit(). */
  if (parent)
  {
    for (struct list_elem *e = list_begin (&parent->child_processes);
      e != list_end (&parent->child_processes);
      e = list_next (e))
    {
      struct process_info *pinfo = list_entry (e, struct process_info, pelem);
      if (pinfo->pid == (pid_t) cur->tid)
      {
        pinfo->has_exited = true;
        sema_up (&pinfo->sema);
        break;
      }
    }
  }


  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Check whether the file is an ELF executable by checking its header. */
bool
is_executable (struct file *file)
{
  ASSERT (file);
  struct Elf32_Ehdr ehdr;
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      return false;
    }

  return true;
}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Make a copy of file_name for setup_stack (). */
  char *fn_copy;
  fn_copy = palloc_get_page (0);
  if (!fn_copy) {
    goto done;
  }
  /* Make a copy of file_name to extract the exec_name. */
  char *fn_copy2;
  fn_copy2 = palloc_get_page (0);
  if (!fn_copy2) {
    palloc_free_page (fn_copy);
    goto done;
  }
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (fn_copy2, file_name, PGSIZE);
  char *str1 = fn_copy2, *saveptr, *exec_name;
  exec_name = strtok_r (str1, " ", &saveptr);

  /* Open executable file. */
  file = filesys_open (exec_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", exec_name);
      goto done; 
    }
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", exec_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, fn_copy))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

  /* The executable is loaded successfully. 
     Add the executable file to the running_executables list. */
  lock_acquire (&running_executables_lock);
  struct running_executable_info *einfo = (struct running_executable_info*)malloc (sizeof(struct running_executable_info));
  if (!einfo)
    success = false;
  else {
    einfo->fptr = file;
    strlcpy (einfo->name, exec_name, sizeof einfo->name);
    list_push_back (&running_executables, &einfo->elem);
  }
  lock_release (&running_executables_lock);

 done:
  /* We arrive here whether the load is successful or not. */
  /* De-allocate fn_copy and fn_copy2. */
  palloc_free_page (fn_copy);
  palloc_free_page (fn_copy2);
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Swap two characters a, b in a string. */
static void 
swap (char *a, char *b) {
  (*a) = (*a) ^ (*b);
  (*b) = (*a) ^ (*b);
  (*a) = (*a) ^ (*b);
}

/* Reverse the arguments in file_name. 
  e.g. file_name := "args-many a b"
       After calling reverse_arguments(file_name):
       file_name = "b a args-many"
*/
static void 
reverse_arguments (char *file_name) {
  if (!file_name)
    return;
  int l = strlen(file_name);
  if (l == 0)
    return;
  char *start = file_name, *end = file_name + l - 1, *tmp;
  /* Reverse the whole string. */
  /* "args-many a b" => "b a ynam-sgra" */
  while (start < end) {
    swap (start, end);
    start++;
    end--;
  }
  /* Reverse each argument. */
  /* "b a ynam-sgra" => "b a args-many" */
  start = file_name; end = start;
  while (*end != '\0') {
    while (*end != ' ' && *end != '\0')
      end++;
    tmp = end;
    end--;
    while (start < end) {
      swap (start, end);
      start++;
      end--;
    }
    if (*tmp == '\0')
      break;
    start = tmp + 1;
    end = start;
  }
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *file_name) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }

  /* Write the executable name (i.e, the first argument), arguments and their address onto the stack. */
  /* The stack should look like:

  low address
      |         [4 zero bytes] [number of arguments] [align bytes] [address of *]
      |         *[address of 1st arguments] ... [address of xth arguments]
      |         [4 zero bytes] [align bytes] [1st argument] ... [xth argument]
     \|/         
  high address

      Note: 1. by adding the size of all arguments and align bytes, the size (in bytes)
            should be a multiple of 4. (align bytes should be 0, 1, 2 or 3)
            2. addresses should be little endian
  */
  if (success) {
    /* debug use. */
    //void *esp_tmp = *esp;

    char *fn_copy = palloc_get_page (0);
    if (fn_copy == NULL)
      return !success;
    strlcpy (fn_copy, file_name, PGSIZE);
    /* Note: according to the official guide, the last argument should be at
       highest address.
       Due to some mysterious reason, the first argument is at the highest
       address in my Pintos setting. Therefore, the following code is commented. */
    //reverse_arguments (fn_copy);

    char *str1 = fn_copy, *saveptr, *token, *args_addr[MAX_ARGS];
    int len = 0, token_len, args = 0;
    token = strtok_r (str1, " ", &saveptr);

    /* Write arguments to stack. */
    while (token != NULL) {
      /* memcpy should also copy '\0' */
      token_len = strlen (token) + 1;
      len += token_len;
      *esp -= token_len;
      /* Save addresses of arguments. */
      args_addr[args] = (char*)malloc(sizeof(char*));
      if (!args_addr[args])
      {
        palloc_free_page (fn_copy);
        for (int i = 0; i < args; i++)
          free (args_addr[i]);
        return !success;
      }
      memcpy (args_addr[args++], esp, 4);
      memcpy (*esp, token, token_len);
      token = strtok_r (NULL, " ", &saveptr);
    }
    /* Align to 4 bytes. */
    /* Note that "-" precedes "&" */
    int word_align = 4 - (len & 0x3);
    if (word_align > 0) {
      *esp -= word_align;
      memset (*esp, 0, word_align);
    }
    /* Write 4 zero bytes. */
    *esp -= 4;
    memset (*esp, 0, 4);
    /* Write addresses of arguments. */
    for(int i = args-1; i >= 0; i--) {
      *esp -= sizeof(char*);
      memcpy (*esp, args_addr[i], 4);
    }
    /* Write the address of [address of 1st argument]. */
    char args0_addr[4];
    memcpy (args0_addr, esp, 4);
    *esp -= 4;
    memcpy (*esp, args0_addr, 4);
    /* Write the number of arguments. */
    *esp -= 4;
    memcpy (*esp, &args, 4);
    /* Write 4 zero bytes. */
    *esp -= 4;
    memset (*esp, 0, 4);

    palloc_free_page (fn_copy);
    for (int i = 0; i < args; i++)
      free (args_addr[i]);

    /* debug use */
    //hex_dump ((uintptr_t)*esp, *esp, esp_tmp-*esp, true);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

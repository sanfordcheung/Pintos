# Pintos

Stanford University CS140 course project.

- [Project 1. Threads](#threads)
- [Project 2. User programs](#user-programs)
- [Project 3. Virtual memory](#virtual-memory)
- [Project 4. File system](#file-system)


## Threads

All [27 test cases](src-proj1/tests/threads/) passed.

### Overview
- Task 1. Alarm clock

In the original implementation of thread sleep, the thread continuously yields
the CPU once it get scheduled. Thus, it "busy waits" until the time required to
sleep has passed. In this task, we modify the thread sleep function to avoid
busy-waiting.

- Task 2. Priority scheduling

By default, the scheduler selects the first thread on the ready list to run.
The ready list is a FIFO queue. Therefore, a thread will not be scheduled until
all the threads in the front have been scheduled.

Now, we want the thread with highest priority to run first. Nevertheless, a problem
called "priority inversion" is introduced. We are required to implement the
 "priority donation" mechanism, which enables threads to donation their own priority
 to some other threads.

- Task 3. Advanced scheduler

In this task, thread priority is dynamically updated. At certain intervals, 
the OS calculates system load average and thread recent CPU time. 

### Statistics
Generated by diffstat program
```
threads/thread.c      |    140 insertions(+), 11 deletions(-)
threads/thread.h      |    16 insertions(+), 2 deletions(-)
threads/synch.c       |    104 insertions(+), 9 deletions(-)
threads/synch.h       |    1 insertion(+)
threads/fixed_point.h |    19 insertions(+)
devices/timer.c       |    36 insertions(+), 4 deletions(-)
```

### Detailed implementation
- 1.1 avoid busy-waiting

In the original implementation of `timer_sleep()` in `devices/timer.c`, 
the current thread that calls this function continuously yields the CPU 
whenever it gets run, until the required sleep time passes. To avoid 
busy-waiting, we resort to `thread_block()` when a thread should sleep. 
Thus, the thread will not be scheduled until some other thread calls 
`thread_unblock()`. A new member `remaining_ticks` is added to `thread` structure 
to record the remaining sleep time. On each time tick, the time interrupt 
handler `timer_interrupt()` will decrement the `remaining_ticks` for 
each thread and, when a thread in the blocked state has 0 remaining ticks, the handler calls 
`thread_unblock()` for it.

**_NOTE:_** We need to check validity of the value passed to `timer_sleep()`.

- 1.2 change the ready list to a priority queue

When we finish task 1.1, all test cases beginning with `alarm-` will pass except the
 `alarm-priority`. The `alarm-priority` case checks that when the alarm clock wakes
  up threads, the higher-priority threads run first. So what happens when a thread
   calls `timer_sleep()`? In the previous task, we implemented thread sleep by putting it to
    blocked state until it was unblocked by the time interrupt handler. When a
     thread is unblocked, it changes to the ready state and was put to the ready
      queue. When a current running thread yields the CPU, the scheduler chooses the
       next thread to run by popping the front of the ready queue. Therefore, by
        changing the ready queue to a priority queue where the higher priority
         threads are in the front, the scheduler will choose the highest priority
          thread to run next. Later, it is required for us to implement the priority
           donation. Hence, the priority of thread on the ready queue can change if a thread receives donation. 
           A better approach is to modify the function
             `next_thread_to_run()` so that the scheduler chooses the highest priority thread.
    
- 2.1 priority change

In the Pinto guide section 2.2.3, it says "when a thread is added to the ready list that has a higher priority than the currently
  running thread, the current thread should immediately yield the processor to the
   new thread". Note that when a thread is created, it will be added to the ready
    list by `thread_unblock()`. We may think of adding a function call `thread_yield()` at the end of
     `thread_unblock()` to implement such functionality. However, the annotation of
      `thread_unblock()` states that "this function does not preempt the running
       thread". Thus, we add `thread_yield()` at the end of `thread_create()` and
        `thread_set_priority()` instead.
           
- 2.2 make the semaphore waiter list and condition variable waiter list to priority queue

This is similar to task 1.2

- 2.3 priority donation

The pintos guide does not give us detailed information. A way to start is to look into the test cases.

case 1. priority-donate-one

|Thread     |Priority    |Lock holding    |Lock waiting    |Action              |
| --------- |:----------:|:--------------:|:--------------:| ------------------:|
|   A       |   31       |  lockA         |                | A is created       |
|   B       |   32       |                | lockA          | B is created       |
|   C       |   33       |                | lockA          | C is created       |
|   A       |   33       |  lockA         |                | B,C donates to A   |

case 2. priority-donate-lower

|Thread     |Priority    |Lock holding    |Lock waiting    |Action              |
| --------- |:----------:|:--------------:|:--------------:| ------------------:|
|   A       |   31       |  lockA         |                | A is created       |
|   B       |   41       |                | lockA          | B is created       |
|   A       |   41       |  lockA         |                | B donates to A      |
|   A       |   41       |  lockA         |                | Set A priority to 21|
|   A       |   21       |                |                | A releases lockA  |

Setting A priority to 21 does not take effect until A releases the lock.

case 3. priority-donate-multiple

|Thread     |Priority    |Lock holding    |Lock waiting    |Action              |
| --------- |:----------:|:--------------:|:--------------:| ------------------:|
|   A       |   31       |  lockA,lockB   |                | A is created       |
|   B       |   32       |                | lockA          | B is created       |
|   C       |   33       |                | lockB          | C is created       |
|   A       |   33       |  lockA,lockB   |                | B,C donates to A  |
|   A       |   32       |  lockA         |                | A releases lockB  |
|   A       |   31       |                |                | A releases lockA  |

case 4. priority-donate-multiple2

|Thread     |Priority    |Lock holding    |Lock waiting    |Action              |
| --------- |:----------:|:--------------:|:--------------:| ------------------:|
|   A       |   31       |  lockA,lockB   |                | A is created       |
|   B       |   34       |                | lockA          | B is created       |
|   C       |   32       |                |                | C is created       |
|   D       |   36       |                | lockB          | D is created       |
|   A       |   36       |  lockA,lockB   |                | B,D donates to A  |
|   A       |   36       |  lockA         |                | A releases lockB  |
|   A       |   31       |                |                | A releases lockA  |

When A releases lockA, its priority doesn't change because D is still waiting for lockA.

case 5. priority-donate-chain

Create 8 threads with increasing priority. `thread[i]` holds `lock[i]` and wait for `lock[i-1]` (i > 0)

When `thread[i]` donates priority `P[i]` to `thread[i-1]`, `thread[i-1]` should also donate `P[i]` because
`P[i] > P[i-1]`. This will continue until `thread[0]` updates its priority.

In total, there are 7 test cases. Now, it is clear to us that we should implement priority donation
such that:

1. When thread A waits for a lock held by thread B, thread A donates its priority P<sub>a</sub>
to thread B. If P<sub>a</sub> > P<sub>b</sub>, thread B updates its priority to P<sub>a</sub>.
Moreover, if thread B is waiting for some other thread C, P<sub>a</sub> will be donated to thread C.

2. When thread A releases a lock but it still hold a list of locks, the priority of thread A is updated as follows: 
let P<sub>m</sub> denote the highest priority among other threads waiting for A, P<sub>a0</sub>
denote the original priority of thread A, then P<sub>a</sub> = max(P<sub>m</sub>, P<sub>a0</sub>).

3. If thread A has updated its priority to P<sub>a</sub> because of received donation(s), at the point
when `thread_set_priority()` is called to set priority to P, then P<sub>a</sub> = max(P<sub>a</sub>, P).

#### implementation
in threads/thread.h
```c
struct thread {
  /* Record the original priority before donation.
     When a thread has not gone back to its original priority, user program
     may try to set the thread a new priority. If the new priority is less
     than the thread priority, we should not update the thread priority because 
     it has received donation that is higher than the new priority. 
     Instead, we update the original priority value so that when the thread returns 
     all donations it received, the priority update takes effect. 
   */
  int priority_original;
  /* The pointer to the lock that the thread is waiting for. 
     When a thread waits for a lock, it is pushed back to the lock waiter list. 
     As there is only one list element for the waiter list, it is guaranteed that 
     a thread can wait for at most 1 lock.*/
  struct lock *lock_waiting;   
  /* A list of locks that the thread is holding. 
     This is useful in the case where a thread received multiple donations. 
     At the point the thread releases a lock and returns the highest donation it 
     received, the thread has the donation from the thread with highest priority that 
     is waiting for any lock in the lock list.  
   */ 
  struct list lock_list;       
}
```

in threads/synch.c
```c
struct semaphore_elem 
{
    int waiter_priority;                /* Used in condition variable only. */
}
```

#### Some functions to dive in

1 - `ptov()`, `vtop()` in threads/vaddr.h

Q: Why does Pintos implement a physical frame address to kernel virtual address mapping?

A: (Pintos guide 4.1.2.2) 80x86 does not provide any way to access memory at a physical address

2 - `running_thread()` in threads/thread.c

Q: How does the OS locate the current running thread?

A: Each thread structure is stored in its own 4KB page. The CPU's stack pointer tells the current stack's top, which is somewhere in the middle of a thread's page. 
Since `struct thread` is always at the beginning of a page, by rounding it down, the thread can be located.

3 - `palloc_get_multiple()` in threads/palloc.c

Q: How does the OS allocate consecutive free pages?

A: Pintos system memory is divided into kernel and user pools.
The user pool is for user memory pages and kernel pool for everything else.
By default, system memory is evenly divided into these two pools.
A memory pool contains a bitmap for free pages. When `palloc_get_multiple()` is called 
for allocating k pages, it scans the bitmap for k consecutive elements that are 
marked as true (which indicates that corresponding pages are available) and 
gets the index of the first available bit. 
Then the starting address of the first available page can be calculated because 
the pool base address, number of pages(i.e, k) and the page size are known. 
The function sets these k bits on the bitmap to false and returns the starting address 
of the first page allocated. 

4 - `malloc()` in threads/malloc.c

Q: How does `malloc()` work?

A: First let's read the description of malloc() implementation:
```c
/*
	The size of each request, in bytes, is rounded up to a power
   of 2 and assigned to the "descriptor" that manages blocks of
   that size.  The descriptor keeps a list of free blocks.  If
   the free list is nonempty, one of its blocks is used to
   satisfy the request.

   	Otherwise, a new page of memory, called an "arena", is
   obtained from the page allocator (if none is available,
   malloc() returns a null pointer).  The new arena is divided
   into blocks, all of which are added to the descriptor's free
   list.  Then we return one of the new blocks.
*/
```
There are two cases depending on how much memory is requested.

(i) If the memory requested is smaller than 1KB,
Pintos maintains an array of block descriptors. 
Each descriptor contains a member block_size describing the size of block elements, 
and a list of free blocks. The size of blocks elements are 16B, 32B, ..., 1KB. 
On requesting x memory, x is rounded up to the nearest power of 2, say y. 
Then we check the block descriptor whose block_size is y. 
If the list of free blocks is not empty, the function `malloc()` returns one of 
the free blocks. Otherwise, `palloc_get_multiple()` is called for allocating a new page
 (the term for this page is "arena"). The arena consists a struct and the remaining
  are blocks.
```
+--------------+ 0
| struct arena |
| some members |
|--------------|
| block 1      |
|--------------|
| block 2      |
|--------------|
| ...          |
|              |
+--------------+ 4KB
```
These blocks in the arena are added to the free list in block descriptor. So now the list is not empty.

(ii) If the memory requested is no less than 1KB,
The requested memory, x is rounded up to the nearest multiple of page size. 
`malloc()` essentially calls `palloc_get_multiple()`.

Q: Is `malloc()` thread-safe?

A: Yes. Each block descriptor has a lock so that no two processes that requests the same amount of block memory can access the block descriptor simultaneously. The page allocation process guarantees thread-safety by locks in both user and kernel pools.

Q: Are there any cases where `malloc()` may result in poor utilization of memory?

A. Yes. For example, if we request for (page size + 1B) memory, `malloc()` actually allocates `(2 * page size)` for us.

5. `free()`

Q: How does the OS detect the behavior that memory is still used after it has already been freed?

A: By setting the freed memory to 0xcc, which can help detect use-after-free bugs.

6. `paging_init()` in threads/init.c & threads/pte.h

Q: What does `paging_init()` do?

A: (1) Get one page as page directory which stores page directory entries (PDE). Every PDE may points to a page table. Since the page size is 4KB and a PDE is 32-bit address, there are at most 1024 PDEs.
   
   (2) Create page directory entries and page table entries (PTE). Each PDE/PTE consists of 20-bit physical address and 12-bit flag bits.
   
   (3) Store the physical address of the page directory into CR3.

## User programs

All [76 test cases](src-proj2/tests/userprog/) passed.

### Overview
- Task 1. Implement minimally to allow a "hello world" user program to work

Up to now, all of the code we have run under Pintos has been part of the Pintos kernel. In this project, we will extend the OS to support user programs. User programs do not have full access to privileged parts of the system. To allow a user program to perform some kernel level task, we will implement a bunch of system calls in this project.

- Task 2. Set up the stack to support argument passing

Before a user program is actually running, we need to set up its stack properly. In this task, we extend the functionality in process.c so that passing arguments to new processes are supported. 

- Task 3. Implement `exec()`, `wait()` and `exit()` syscalls

This is the most difficult task in project 2. These three syscalls are important because they will be invoked everytime a parent process creates a child process and, the parent process wants to retrieve the child process's exit status. Moreover, when a process exits, we need to decide which resources should be de-allocated and which should be kept. 

- Task 4. Implement the remaining syscalls

The remaining syscalls are mostly for file I/O. 

### Statistics
Generated by diffstat program
```
threads/thread.c      |    41 insertions(+)
threads/thread.h      |    57 insertions(+)
userprog/syscall.c    |    421 insertions(+), 2 deletions(-)
userprog/syscall.h    |    1 insertion(+), 1 deletion(-)
userprog/process.c    |    363 insertions(+), 13 deletions(-)
userprog/process.h    |    3 insertions(+), 1 deletion(-)
userprog/exception.c  |    6 insertions(+), 4 deletions(-)
```

### Detailed implementation
- 1.1 implement a simple `process_wait()` in userprog/process.c

We should first notice two important functions in userprog/process.c:

```c
/* Starts a new thread running a user program loaded from
FILENAME.  The new thread may be scheduled (and may even exit)
before process_execute() returns.  Returns the new process's
thread id, or TID_ERROR if the thread cannot be created. 
*/
tid_t process_execute (const char *file_name); 
/* Waits for thread TID to die and returns its exit status.
*/
int process_wait (pid_t pid) ;
```

When we run a user program, the main thread calls `process_execute()` to load the
program. Next it calls `process_wait()` to wait for the user program to exit. Note that
the `process_wait()` does not wait at all for now:

```c
int process_wait (tid_t child_tid UNUSED) 
{
  return -1;
}
```

A simple solution can be a semaphore. The semaphore is down when `process_wait()` is called.
In `process_exit()`, the semaphore is up so that when a child process exits, the parent process waiting for it can be unblocked.

- 1.2 pass the file name to `thread_create()` and `filesys_open()` (which is in the 
function `load()` in userprog/process.c)

The argument `const char *file_name` passed into the function `process_execute()` is the command line consisting the actual executable name (the executable is an ELF file) and all the arguments. We should pass the executable name to  `thread_create()` and `filesys_open()` instead.

- 1.3 implement a simple form of syscall `exit()`

A user program invokes the system call `exit()` eventually unless it is killed by the kernel thread
somewhere in the middle of its execution. To run a "hello world" user program properly, we need to implement a simple `exit()` syscall. So what happens when a user process invokes a syscall?

In userprog/syscall.c:
```c
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
```
The user process calls `exit()` handled by the system call handler in the kernel.
Now we register for a syscall `exit()` in the syscall handler:

```c
switch(*(int*)f->esp)
  {
      case SYS_EXIT:
      {
          int status = *((int*)f->esp + 1);
          printf("%s: exit(%d)\n", thread_current ()->name, status);
          thread_exit ();
      }
  }
```

`((int*)f->esp + 1)` is the pointer pointing to the first argument.

- 1.4 implement writing to standard out and set the `esp` pointer

User programs will invoke `write()` whenever it writes to file or the standard out (with the file descriptor STDOUT_FILENO). Calling `putbuf()` will write all the contents from a buffer to standard out.

Now if you try to run the first test case, you will notice an error message:

```bash
+ Page fault at 0xc0000008: rights violation error reading page in user context.
+ args-none: dying due to interrupt 0x0e (#PF Page-Fault Exception).
when you run a test (for example, `args-many`)
```

This happens because when a user program invokes a syscall, it reads the syscall number from `*esp`. Now the pointer points to a kernel space memory.

Just change
```c
*esp = PHYS_BASE;
```
to
```c
*esp = PHYS_BASE - 12;
```
in setup_stack() in userprog/process.c

When you finish the above five steps, you can run a "hello world" program that prints some message to the console and exit properly.

- 2 Set up the stack

Please refer to the official guide:
https://web.stanford.edu/class/cs140/projects/pintos/pintos_3.html#SEC51
for detailed and clear explanation on this task.

Consider the command `/bin/ls -l foo bar` as an example. The general steps are the following:

- Break the command into tokens `/bin/ls`, `-l`, `foo` and `bar`. You may want to use `strtok_r()` declared in the string.h library.

- Place the words at the top of the stack in reverse order.

- Write 0, 1, 2 or 3 zero bytes so that the content is word-aligned.

- Write a `NULL` pointer (fake word address) indicating the end of arguments.

- Write the address of words in reverse order.

- Write the address of `argv[0]` and number of arguments (`argc`)

- Write a `NULL` pointer (fake return address)

The state of the stack should look like (assuming PHYS_BASE is 0xc0000000):

|Address     |Name    |Data    |Type    |
| --------- |:----------:|:--------------:|:--------------:|
|0xbffffffc      |argv[3][...]    |bar\0    |char[4] |
|0xbffffff8      |argv[2][...]    |foo\0    |char[4] |
|0xbffffff5      |argv[1][...]    |-l\0       |char[3] |
|0xbfffffed      |argv[0][...]    |/bin/ls\0    |char[8] |
|0xbfffffec       |word-align    |0    |uint8_t |
|0xbfffffe8       |    argv[4]  |  0   | char * |
|0xbfffffe4       |    argv[3]   | 0xbffffffc   | char * |
|0xbfffffe0    |  argv[2]  |  0xbffffff8  |  char * |
|0xbfffffdc  |  argv[1]  |  0xbffffff5  |  char * |
|0xbfffffd8 |   argv[0]  |  0xbfffffed |   char * |
|0xbfffffd4  |  argv   | 0xbfffffd8  |  char ** |
|0xbfffffd0   | argc   | 4   | int |
|0xbfffffcc    |return address |   0  |  void (*) () |

**_NOTE:_** Addresses should be little endian

A note on function `strtok_r()`:
```c
/* Note: 1. Don't free(s1) if you are still using token.
         2. strtok_r() modifies `s1` even if it is const char * .
*/
token = strtok_r(s1, s2, saveptr);
```

It is a good idea to use `hex_dump()` to check whether you have set up the stack correctly. Also, all dynamically allocated memory should be freed when it is not used any more.

- 3.1 `exec()` and `process_execute()`

The `exec()` syscall calls `process_execute()`  to start a new thread running a user program.
However, the user program may fail to load. How should the parent process know if the program is successfully loaded? We may use a semaphore or a lock to ensure the parent process will wait for the child process to finish load.  

- 3.2 `wait()` and `process_wait()`

A parent process waits for a child process and retrieves its exit status by the `wait()` syscall. Processes may spawn any number of children and wait for them in any order. Some situations for you to consider:

- What if the child process has already terminated by the time its parent calls `wait()`? How should the parent process know whether it has terminated or not? How to retrieve its exit status?

- What if the child process is terminated by the kernel due to an exception (e.g, accessing an invalid page)?

- What if a process waits for another process that is not its child?

- What if a process waits for a child more than once?

- 3.3 `exit()` and `process_exit()`

When a process exits, we need to decide which resources should be de-allocated and which should be kept. If some dynamically allocated memory (allocated by `palloc`, `malloc` or `calloc`) are leaked, we will not pass the `multi-oom` test case for sure. Remember also to check for the set up stack part.

Some structure to store process information will not be freed until the parent process exits, because it is useful for the parent to retrieve the exit status.

- 4.1 validate pointers in syscall

- 4.2 deny write to running executables

#### implementation
in threads/thread.h, 
some new members in `struct thread`:
```c
struct thread {
  struct thread *parent;              /* Pointer to parent thread. */
  struct list open_files;             /* A list of files opened by the thread. */ 
  int next_fd;                        /* The file descriptor for the next open file. */
  struct list child_processes;        /* A list of child processes. */
}
```
for file manipulation in syscall:
```c
/* For user process.
   File descriptor structure is used for files opened by a process.
   By design, each process has an independent set of file descriptors.
   When a single file is opened for more than once, whether by a single process
   or different processes, each file open returns a new file descriptor.
   fd 0 and 1 are reserved for STDIN_FILENO and STDOUT_FILENO
*/
struct file_descriptor {
  int fd;                   /* The file descriptor. */
  char name[16];            /* For project 2, file names are limited to 14 characters. */
  struct file *fptr;        /* Pointer to the file. */
  struct list_elem felem;   /* List element for the open_files list. */
};
```
for storing some process information, sychronization between parent and child process:
```c
/* For user process.
   Process info structure is used to store the child process's pid, exit status, etc.
   When a thread exits, it frees all elements in the child_processes list. */
struct process_info {
  pid_t pid;                /* Child process's process id. */
  bool has_exited;          /* Has the process exited? */
  bool is_waited;           /* Is the process waited by its parent process? */
  int status;               /* If the process has exited, it stores the exit status. */
  struct list_elem pelem;   /* List element for the child_processes list. */
  struct semaphore sema;    /* Semaphore for the parent process to wait for child process. */
};
```
Running executables should not be modified. A global list is maintained to identify which are running executables:
```c
/* A list of running executables. */
struct list running_executables;
/* Lock used when a process is manipulating running_executables list. */
struct lock running_executables_lock;
/* A struct for storing running executable's file name. */
struct running_executable_info {
  struct file *fptr;         /* Pointer to the executable file. */
  char name[16];             /* File name. */
  struct list_elem elem;     /* List element for the running_executables list. */
};
```

#### A note on `multi-oom` test case

- Error: crashed child should return -1

Solution: Check whether user process exits with -1 when it causes a page fault

- Error: expected depth: x, actual depth: y

Solution: check whether all malloc and palloc resources are freed when they are no longer used

#### Some functions to dive in


## Virtual memory

## File system



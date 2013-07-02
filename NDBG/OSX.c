//
//  OSX.c
//  NDBG
//
//  Created by System Administrator on 6/30/13.
//  Copyright (c) 2013 System Administrator. All rights reserved.
//

#include "OSX.h"




//////////////////////////////////////////////// MACH EXCEPTION HANDLING CODE

void mach_assert(char *msg, kern_return_t kr) {
    if (kr != KERN_SUCCESS) {
        mach_error(msg, kr);
        exit(-1);
    }
}

uint64_t get_eip (thread_state_t stateptr) {
    x86_thread_state64_t *state = (x86_thread_state64_t *)stateptr;
    return(state->__rip);
}

kern_return_t catch_mach_exception_raise(mach_port_t exception_port,mach_port_t thread,mach_port_t task,exception_type_t exception,
                                               exception_data_t code,mach_msg_type_number_t code_count) {
    kern_return_t r;
    char *addr;
    
    thread_state_flavor_t flavor = x86_EXCEPTION_STATE;
    mach_msg_type_number_t exc_state_count = x86_EXCEPTION_STATE_COUNT;
    x86_exception_state_t exc_state;
    
    /* we should never get anything that isn't EXC_BAD_ACCESS, but just in case */
    if(exception != EXC_BREAKPOINT ) {
        /* We aren't interested, pass it on to the old handler */
        fprintf(stderr,"Exception: 0x%x Code: 0x%x 0x%x in catch....\n",
                exception,
                code_count > 0 ? code[0] : -1,
                code_count > 1 ? code[1] : -1);
        return 1;
    }
    
    r = thread_get_state(thread,flavor, (natural_t*)&exc_state,&exc_state_count);
    if (r != KERN_SUCCESS) DIE("thread_get_state");
    
    /* This is the address that caused the fault */
    addr = (char*) exc_state.ues.es64.__faultvaddr;
    
    uint64_t eip = get_eip((thread_state_t)&exc_state);
    
    printf("BP catched at addr 0x%x (eip at 0x%x)\n", addr, eip);
    
    /* you could just as easily put your code in here, I'm just doing this to
     point out the required code */
    if(!my_handle_exn(addr, code[0])) return 1;
    
    return KERN_SUCCESS;
}
kern_return_t catch_mach_exception_raise_state(mach_port_name_t exception_port,
                                               int exception, exception_data_t code, mach_msg_type_number_t codeCnt,
                                               int flavor, thread_state_t old_state, int old_stateCnt,
                                               thread_state_t new_state, int new_stateCnt) {
    
    ABORT("catch_exception_raise_state");
    return(KERN_INVALID_ARGUMENT);
}
kern_return_t catch_mach_exception_raise_state_identity(mach_port_name_t exception_port, mach_port_t thread, mach_port_t task, int exception,
                                               exception_data_t code, mach_msg_type_number_t codeCnt, int flavor, thread_state_t old_state,
                                               int old_stateCnt, thread_state_t new_state, int new_stateCnt) {
    ABORT("catch_exception_raise_state_identity");
    return(KERN_INVALID_ARGUMENT);
}

void catch_exceptions(void) {
    puts("catching...\n");
    
    mach_msg_return_t r;
    struct {
        mach_msg_header_t head;
        char data[256];
    } reply;
    struct {
        mach_msg_header_t head;
        mach_msg_body_t msgh_body;
        char data[1024];
    } msg;
    
    for(;;) {
        r = mach_msg(&msg.head, MACH_RCV_MSG|MACH_RCV_LARGE, 0, sizeof(msg), Proc.exception_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(r != MACH_MSG_SUCCESS) DIE("mach_msg");
        if(!mach_exc_server(&msg.head,&reply.head)) DIE("exc_server");
        r = mach_msg( &reply.head, MACH_SEND_MSG, reply.head.msgh_size, 0, MACH_PORT_NULL,  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(r != MACH_MSG_SUCCESS) DIE("mach_msg");
    }
}

void exn_init(void) {
    kern_return_t r;
    mach_port_t me;
    pthread_t thread;
    pthread_attr_t attr;
    exception_mask_t mask;
    
    puts("attaching...\n");
    mach_assert("task_for_pid()\n", task_for_pid(mach_task_self(), Proc.pid, &Proc.task));
    
    me = mach_task_self();
    r = mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, &Proc.exception_port);
    if(r != MACH_MSG_SUCCESS) DIE("mach_port_allocate");
    
    r = mach_port_insert_right(me, Proc.exception_port, Proc.exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if(r != MACH_MSG_SUCCESS) DIE("mach_port_insert_right");
    
    /* for others see mach/exception_types.h */
    mask = EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT;
    
    /* set the new exception ports */
    r = task_set_exception_ports(Proc.task,mask,Proc.exception_port,EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,MACHINE_THREAD_STATE);
    if(r != MACH_MSG_SUCCESS) DIE("task_set_exception_ports");
    
    /*
     // start new thread //
     if(pthread_attr_init(&attr) != 0) DIE("pthread_attr_init");
     if(pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED) != 0)
     DIE("pthread_attr_setdetachedstate");
     
     if(pthread_create(&thread,&attr,exc_thread,NULL) != 0)
     DIE("pthread_create");
     pthread_attr_destroy(&attr);
     */
    catch_exceptions();
    
}

static char *data;
int my_handle_exn(char *addr, integer_t code) {
    if(code == KERN_INVALID_ADDRESS) {
        fprintf(stderr,"Got KERN_INVALID_ADDRESS at %p\n",addr);
        exit(1);
    }
    if(code == KERN_PROTECTION_FAILURE) {
        fprintf(stderr,"Got KERN_PROTECTION_FAILURE at %p\n",addr);
        if(addr == NULL) {
            fprintf(stderr,"Tried to dereference NULL");
            exit(1);
        }
        return 0; // forward it
    }
    
    /* filter out anything you don't want in the catch_exception_raise... above
     and forward it */
    fprintf(stderr,"Got unknown code %d at %p\n",(int)code,addr);
    return 0;
}

//////////////////////////////////////////////// DEBUGGER CODE

int attach(void) {
    puts("attaching...");
    assert(task_for_pid(mach_task_self(), Proc.pid, &Proc.task) == KERN_SUCCESS);
    
    mach_port_t me;
    exception_mask_t mask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC | EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT | EXC_MASK_SYSCALL;
    
    // Create a port by allocating a receive right, and then create a send right
    // accessible under the same name.
    me = mach_task_self();
    mach_assert("mach_port_allocate()",       mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, &Proc.exception_port));
    mach_assert("mach_port_insert_right()",   mach_port_insert_right(me, Proc.exception_port, Proc.exception_port, MACH_MSG_TYPE_MAKE_SEND));
    
    /* get the old exception ports */
    //mach_assert("mach_get_exception_ports()", task_get_exception_ports(targetTask, mask, old_exc_ports.masks, &old_exc_ports.count, old_exc_ports.ports, old_exc_ports.behaviors, old_exc_ports.flavors));
    
    /* set the new exception port */
    mach_assert("task_set_exception_ports()", task_set_exception_ports(Proc.task, mask, Proc.exception_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE));
    
    
    /*
     pthread_t thread;
     pthread_attr_t attr;
     if (pthread_attr_init(&attr) != 0) {
     printf("pthread_attr_init");
     exit(0);
     }
     if (pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED) != 0) {
     printf("pthread_attr_setdetachedstate");
     exit(0);
     }
     
     if (pthread_create(&thread, &attr, my_mach_msg_server, NULL) != 0) {
     printf("pthread_create");
     exit(0);
     }
     pthread_attr_destroy(&attr);
     */
    
    if (Proc.exception_port == 0)
        return(0);
    
    return(1);
}

int detach(void) {
    mach_port_t me = mach_task_self();
    mach_assert("[ERROR] mach_port_deallocate()", mach_port_deallocate(me, Proc.exception_port));
    return 0;
}

void CreateProcess(void) {
    printf("[DEBUG] Creating process %s %s\n", Proc.Name, Proc.Args);
    
    posix_spawnattr_t attr;
    int retval      = 0;
    size_t copied   = 0;
    short flags     = 0;
    cpu_type_t cpu  = 0;
    
    // default target is 64bits
    cpu = CPU_TYPE_X86_64;
    
    posix_spawnattr_init (&attr);
    // set process flags
    // the new process will start in a suspended state and permissions reset to real uid/gid
    flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_START_SUSPENDED;
    // disable ASLR, Snow Leopard will just ignore this flag
    flags |= _POSIX_SPAWN_DISABLE_ASLR;
    
    posix_spawnattr_setflags(&attr, flags);
    
    // reset signals
    sigset_t no_signals;
    sigset_t all_signals;
    sigemptyset (&no_signals);
    sigfillset (&all_signals);
    posix_spawnattr_setsigmask(&attr, &no_signals);
    posix_spawnattr_setsigdefault(&attr, &all_signals);
    // set the target cpu to be used, due to fat binaries
    posix_spawnattr_setbinpref_np(&attr, 1, &cpu, &copied);
    
    char *spawnedEnv[] = { NULL };
    
    int cmd_line_len = (int) strlen(Proc.Args);
    if (cmd_line_len >= ARG_MAX) {
        fprintf(stderr, "[ERROR] arg list too long\n");
        exit(1);
    }
    
    if (cmd_line_len) {
        // parse command line;
        int i = 0;
        char *p = strchr(Proc.Args, ' ');
        char *q = (char *)Proc.Args;
        
        char **argv = (char **)malloc(sizeof(char*) * 256);
        while (p && i < 253) {
            *p = '\0';
            argv[i++] = q;
            q = p + 1;
            p = strchr(q, ' ');
        }
        errno = 0;
        argv[i] = q;
        argv[i+1] = NULL;
        printf("[DEBUG] Spawning %s %s %s\n", argv[0], argv[1], argv[2]);
        fflush(stdout);
        if (!posix_spawn(&Proc.pid, argv[0], NULL, &attr, argv, spawnedEnv)) {
            fprintf(stderr, "[ERROR] Could not spawn debuggee: %s\n", strerror(retval));
            exit(1);
        }
        free(argv);
    }
    else {
        fflush(stdout);
        // execute with no arguments
        char *argv[] = {(char *)Proc.Name, NULL};
        printf("[DEBUG] Spawning %s (no arguments)...\n", Proc.Name);
        retval = posix_spawnp(&Proc.pid, argv[0], NULL, &attr, argv, spawnedEnv);
        if (retval) {
            fprintf(stderr, "[ERROR] Could not spawn debuggee: %s\n", strerror(retval));
            exit(1);
        }
    }
    // parent: initialize the mach port into the debugee
    retval = attach();
    // failed to attach
    if (retval == 0)
        clean_up();
    
    assert(task_for_pid(mach_task_self(), Proc.pid, &Proc.task) == KERN_SUCCESS);
    // suspend_allthreads();
    // and now we can continue the process, threads are still suspended!
    kill(Proc.pid, SIGCONT);
    fflush(stdout);
}

struct Breakpoint SetBreakpoint(uint64_t Address) {
    Proc.BPID++;
    
    struct Breakpoint B;
    B.ID = Proc.BPID;
    B.address = Address;
    B.active  = true;
    B.max_hits = -1;
    B.description = "";
    B.Orig_Inst = 0;
    B.hitcount = 0;
    
    
    mach_assert("[ERROR] mach_vm_protect()",        mach_vm_protect(Proc.task, B.address, 1, false, VM_PROT_READ | VM_PROT_WRITE));
    mach_vm_size_t nread;
    mach_assert("[ERROR] mach_vm_read_overwrite()", mach_vm_read_overwrite(Proc.task, B.address, 1, (mach_vm_address_t) &B.Orig_Inst, &nread));
    
    unsigned char BP = {0xCC};
    mach_assert("[ERROR] mach_vm_write()",          mach_vm_write(Proc.task, B.address, (vm_offset_t) &BP, 1));
    mach_assert("[ERROR] mach_vm_protect()",        mach_vm_protect(Proc.task, B.address, 1, false, VM_PROT_READ | VM_PROT_EXECUTE));
    
    return B;
}

struct Breakpoint SetSmartBreakpoint(uint64_t Address, int mHits, char *description) {
    Proc.BPID++;
    
    struct Breakpoint B;
    B.ID = Proc.BPID;
    B.address = Address;
    B.active  = true;
    B.max_hits = mHits;
    B.description = description;
    
    mach_assert("[ERROR] mach_vm_protect()",        mach_vm_protect(Proc.task, B.address, 1, false, VM_PROT_READ | VM_PROT_WRITE));
    mach_vm_size_t nread;
    mach_assert("[ERROR] mach_vm_read_overwrite()", mach_vm_read_overwrite(Proc.task, B.address, 1, (mach_vm_address_t) &B.Orig_Inst, &nread));
    
    unsigned char BP = {0xCC};
    mach_assert("[ERROR] mach_vm_write()",          mach_vm_write(Proc.task, B.address, (vm_offset_t) &BP, 1));
    mach_assert("[ERROR] mach_vm_protect()",        mach_vm_protect(Proc.task, B.address, 1, false, VM_PROT_READ | VM_PROT_EXECUTE));
    
    return B;
}

void DelBreakPoint(struct Breakpoint B) {
    Proc.BPID--;
    
    mach_assert("[ERROR] mach_vm_protect()",        mach_vm_protect(Proc.task, B.address, 1, false, VM_PROT_READ | VM_PROT_WRITE));
    mach_assert("[ERROR] mach_vm_write()",          mach_vm_write(Proc.task, B.address, (vm_offset_t) &B.Orig_Inst, 1));
    mach_assert("[ERROR] mach_vm_protect()",        mach_vm_protect(Proc.task, B.address, 1, false, VM_PROT_READ | VM_PROT_EXECUTE));
}

void clean_up(void) {
    resume_allthreads();
    kill(Proc.pid, SIGCONT);
    kill(Proc.pid, SIGKILL);
    printf("[DEBUG] clean_exit\n");
    exit(0);
}
//////////////////////////////////////////////// TASK AND THREAD HANDLING

void check_privileges(void) {
    struct group *mygroup;
    mygroup = getgrnam("procmod");
    int permissionstatus = 0;
    
    if (getuid() != 0)
        permissionstatus = 1;
    if (getegid() == mygroup->gr_gid)
        permissionstatus = 0;
    if (permissionstatus) {
        fprintf(stderr, "[ERROR]: This program must be run as root or with procmod group permission\n");
        exit(1);
    }
}

pid_t get_pid(void) {
    struct kinfo_proc *procs = NULL, *newprocs;
    char          thiscmd[MAXCOMLEN + 1];
    pid_t         thispid;
    int           mib[4];
    size_t        miblen;
    int           i, st, nprocs;
    size_t        size;
    size = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    mib[3] = 0;
    miblen = 3;
    
    sysctl(mib, (unsigned int)miblen, NULL, &size, NULL, 0);
    do {
        size += size / 10;
        newprocs = realloc(procs, size);
        if (newprocs == 0) {
            if (procs)
                free(procs);
            printf("could not reallocate memory");
        }
        procs = newprocs;
        st = (int)sysctl(mib, (unsigned int)miblen, procs, &size, NULL, 0);
    }
    while (st == -1 && errno == ENOMEM);
    nprocs = (int)size /sizeof(struct kinfo_proc);
    for (i = 0; i < nprocs; i++) {
        thispid = procs[i].kp_proc.p_pid;
        strncpy(thiscmd, procs[i].kp_proc.p_comm, MAXCOMLEN);
        thiscmd[MAXCOMLEN] = '\0';
        if (strcmp(Proc.Name, thiscmd) == 0) {
            Proc.pid = thispid;
            free(newprocs);
            return(thispid);
        }
    }
    free(procs);
    return(-1);
}

int suspend_thread(unsigned int thread) {
    assert(thread_suspend(thread) == KERN_SUCCESS);
    return(0);
}
void suspend_allthreads(void) {
    printf("[DEBUG] Suspending all threads...\n");
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count,i;
    
    assert(task_threads(Proc.task, &thread_list, &thread_count) == KERN_SUCCESS);
    if (thread_count > 0) {
        i = thread_count;
        while (i--) {
            suspend_thread(thread_list[i]);
        }
    }
}
bool check_thread_state(unsigned thread, int state) {
    unsigned int size = THREAD_BASIC_INFO_COUNT;
    struct thread_basic_info info;
    
    assert(thread_info(thread, THREAD_BASIC_INFO, (thread_info_t) &info, &size) == KERN_SUCCESS);
    if (info.run_state != state)
        return(false);
    
    return (true);
}
bool check_all_thread_states(int state) {
    printf("[DEBUG] Checking run_state of all threads...\n");
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count, i;
    assert(task_threads(Proc.task, &thread_list, &thread_count) == KERN_SUCCESS);
    
    if (thread_count > 0) {
        i = thread_count;
        while (i--) {
            if (check_thread_state((thread_list[i]), state) == false)
                return (false);
        }
    }
    return (true);
}
int resume_thread(unsigned int thread) {
    unsigned int size = THREAD_BASIC_INFO_COUNT;
    struct thread_basic_info info;
    assert(thread_info(thread, THREAD_BASIC_INFO, (thread_info_t) &info, &size) == KERN_SUCCESS);
    
    int i;
    for(i = 0; i < info.suspend_count; i++) {
        assert(thread_resume(thread) == KERN_SUCCESS);
    }
    return 0;
}
void resume_allthreads(void) {
    printf("[DEBUG] Resuming all threads...\n");
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count,i;
    
    assert(task_threads(Proc.task, &thread_list, &thread_count) == KERN_SUCCESS);
    if (thread_count > 0) {
        i = thread_count;
        while (i--) {
            resume_thread(thread_list[i]);
        }
    }
}



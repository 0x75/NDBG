//
//  OSX.h
//  NDBG
//
//  Created by System Administrator on 6/30/13.
//  Copyright (c) 2013 System Administrator. All rights reserved.
//

#ifndef NDBG_OSX_h
#define NDBG_OSX_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include <spawn.h>
#include <pthread.h>
#include <grp.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_init.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_status.h>
#include <mach/thread_info.h>
#include <mach/exception.h>
#include <mach/exception_types.h>

#include "mach_exc.h"

#define MAX_EXCEPTION_PORTS 16
#define _POSIX_SPAWN_DISABLE_ASLR           0x00000100

#define DIE(x) do { fprintf(stderr,"%s failed at %d\n",x,__LINE__); exit(1); } while(0)
#define ABORT(x) do { fprintf(stderr,"%s at %d\n",x,__LINE__); } while(0)


struct Process {
    char        *Name;
    char        *Args;
    pid_t       pid;
    task_t      task;
    mach_port_t exception_port;
    int         BPID;
} Proc;

struct Breakpoint {
    int         ID;
    bool        active;
    uint64_t    address;
    char        *description;
    int         hitcount;
    int         max_hits;                       // if max_hits = -1 BP will remain installed until removed by user
                                                // if max_hits >= 0 (for example 10) BP will automatically be uninstalled if hitcount == max_hits
    unsigned char        Orig_Inst;
} BP;

// Mach
void catch_exceptions(void);
void exn_init(void);

// Debuggger
int attach(void);
int detach(void);
void CreateProcess(void);
struct Breakpoint SetBreakpoint(uint64_t);
struct Breakpoint SetSmartBreakpoint(uint64_t, int, char *);
void DelBreakPoint(struct Breakpoint);
void clean_up(void);

// Task/Thread Handling
pid_t get_pid(void);
void check_privileges(void);
int suspend_thread(unsigned int);
void suspend_allthreads(void);
bool check_thread_state(unsigned, int);
bool check_all_thread_states(int);
int resume_thread(unsigned int);
void resume_allthreads(void);


#endif

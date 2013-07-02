//
//  main.c
//  NDBG
//
//  Created by System Administrator on 6/30/13.
//  Copyright (c) 2013 System Administrator. All rights reserved.
//
#include "OSX.h"


int main(int argc, char *argv[]) {
    
    Proc.Name = "/Users/Nico/succ";
    Proc.Args = "";
    
    /* fire up the exception thread */
    //exn_init();
    
    check_privileges();
    CreateProcess();
    printf("pid %i\n",Proc.pid);
    SetBreakpoint(0x0000000100000e8d);
     catch_exceptions();
   // exn_init()
    
    puts("exiting...");
    return 0;
}

#pragma once
typedef unsigned long guardT(
  unsigned long p0,
  unsigned long p1,
  unsigned long p2,
  unsigned long p3,
  unsigned long p4,
  unsigned long p5);


#define GUARD_NUM_SYSCALLS 20
extern guardT *syscall_to_guard[GUARD_NUM_SYSCALLS];

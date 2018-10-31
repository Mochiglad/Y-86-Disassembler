
#include <stdio.h>
#include <unistd.h>
#include "printRoutines.h"

int samplePrint(FILE *out) {

  int res = 0;

  unsigned long addr = 0x1016;
  char * r1 = "%rax";
  char * r2 = "%rdx";
  char * inst1 = "rrmovq";
  char * inst2 = "jne";
  char * inst3 = "irmovq";
  char * inst4 = "mrmovq";
  unsigned long destAddr = 8193;
  
  res += fprintf(out, "%016lx: %-22s%-8s%s, %s\n", 
		 addr, "2002", inst1, r1, r2);

  addr += 2;
  res += fprintf(out, "%016lx: %-22s%-8s%#lx\n", 
		 addr, "740120000000000000", inst2, destAddr);

  addr += 9;
  res += fprintf(out, "%016lx: %-22s%-8s$%#lx, %s\n", 
		 addr, "30F21000000000000000", inst3, 16L, r2);

  addr += 10;
  res += fprintf(out, "%016lx: %-22s%-8s%#lx(%s), %s\n", 
		 addr, "50020000010000000000", inst4, 65536L, r2, r1); 
  
  addr += 10;
  res = fprintf(out, "%016lx: %-22s%-8s%s, %s\n", 
		addr, "2020", inst1, r2, r1);
  
  addr += 2;
  res = fprintf(out, "%016lx: %-22s%-8s%#lx\n", 
		addr, "FFFFFFFFFFFFFFFF", ".quad", 0xFFFFFFFFFFFFFFFFL);

  return res;
}  
  

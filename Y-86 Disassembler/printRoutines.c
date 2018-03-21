
#include <stdio.h>
#include <unistd.h>
#include "printRoutines.h"

// You probably want to create a number of printing routines in this file.
// Put the prototypes in printRoutines.h


/*********************************************************************
   Details on print formatting can be found by reading the man page
   for printf. The formatting rules for the disassembler output are
   given below.

   The printing rules are as follows:
   
     1) Each line is to begin with the hex printed value of the
        address followed immediately by a ": ". Leading zeros are to
        be printed for the address, which is 8 bytes long.

     2) After the ": " there are to be 22 characters before the start
        of the printing of the instruction mnemonic. In those 22
        characters the program is to print, left justified, the hex
        representation of the memory values corresponding to the
        assembler instruction and operands that were printed.

     3) The instruction field follows, and is 8 characters long. The
        instruction (or .quad/.byte directive) is to be printed left
        justified in those 8 characters (%-8s). All instructions are
        to be printed in lower case.

     4) After the instruction field the first operand is to be
        printed. No extra space is needed, since the 8 characters for
        instructions is enough to leave a space between instruction
        and operands.
 
     5) If there is a second operand then there is to be a comma
        immediately after the first operand (no spaces) and then a
        single space followed by the second operand.

     6) The rules for printing operands are as follows: 

         a) Registers: A register is to be printed with the % sign and
            then its name. (.e.g. %rsp, %rax etc) Register names are
            printed in lower case.
 
         b) All numbers are to be printed in hex with the appropriate
            leading 0x. Leading zeros are to be suppressed. A value of
            zero is to be printed as "0x0". The numbers are assumed to
            be unsigned.

         c) A base displacement address is to be printed as D(reg)
            where the printing of D follows the rules in (b), and the
            printing of reg follows the rules in (a). Note there are
            no spaces between the D and "(" or between reg and the "("
            or ")".
        
         d) An address such as that used by a call or jump is to be
            printed as in (b). A value printed in a .quad or .byte
            directive uses the same format. For these instructions no
            "$" is required.

         e) A constant (immediate value), such as that used by irmovq
            is to be printed as a number in (b) but with a "$"
            immediately preceeding the 0x without any spaces.
           
     7) The unconditional move instruction is to be printed as rrmovq,
        while the conditional move is to be printed as cmovXX, where
        XX is the condition (e.g., cmovle).

     8) The mnemonics for the instruction are to conform to those
        described in the textbook and lecture slides.

     9) The arguments for the format string in the example printing
        are strictly for illustrating the spacing. You are free to
        construct the output however you want.
 
********************************************************************************/
 
/* This is a function to demonstrate how to do print formatting. It
 * takes the file descriptor the I/O is to be done to. You are not
 * required to use the same type of printf formatting, but you must
 * produce the same result.
 */
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
  

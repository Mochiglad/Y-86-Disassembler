#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "printRoutines.h"

#define ERROR_RETURN -1
#define SUCCESS 0

int main(int argc, char **argv) {
  
  FILE *machineCode, *outputFile;
  long currAddr = 0; 

  // Verify that the command line has an appropriate number
  // of arguments

  if (argc < 3 || argc > 4) {
    printf("Usage: %s InputFilename OutputFilename [startingOffset]\n", argv[0]);
    return ERROR_RETURN;
  }

  // First argument is the file to read, attempt to open it 
  // for reading and verify that the open did occur.
  machineCode = fopen(argv[1], "rb");

  if (machineCode == NULL) {
    printf("Failed to open %s: %s\n", argv[1], strerror(errno));
    return ERROR_RETURN;
  }

  // Second argument is the file to write, attempt to open it 
  // for writing and verify that the open did occur.
  outputFile = fopen(argv[2], "w");

  if (outputFile == NULL) {
    printf("Failed to open %s: %s\n", argv[2], strerror(errno));
    fclose(machineCode);
    return ERROR_RETURN;
  }

  // If there is a 3rd argument present it is an offset so
  // convert it to a value. 
  if (4 == argc) {
    // See man page for strtol() as to why we check for errors by examining errno
    errno = 0;
    currAddr = strtol(argv[3], NULL, 0);
    if (errno != 0) {
      perror("Invalid offset on command line");
      fclose(machineCode);
      fclose(outputFile);
      return ERROR_RETURN;
    }
  }

  printf("Opened %s, starting offset 0x%lX\n", argv[1], currAddr);
  printf("Saving output to %s\n", argv[2]);


  // Your code starts here.
  
  int haltFlag = 0; //flag to ensure only one halt is printed
  fseek(machineCode, 0, SEEK_END); //find the end of the code
  int inputLength = ftell(machineCode); //find the number of bytes in the code
  rewind(machineCode); //re-point pointer to the start of the file
  unsigned char *input = (unsigned char *)malloc((inputLength + 1)*sizeof(char)); //input array that contains unsigned bytes.
  fread(input, inputLength, 1, machineCode); //read the file and store it in an array
  int startAddress = currAddr; //beginning address
  
  //Set the offset
  if(argv[3] == 0) {
	  currAddr += getStartIndex(input);
	  startAddress = getStartIndex(input);
  }

  //Iterate until there is no more input, print each instruction as each iteration occurs.
  for(int i = startAddress; i < inputLength;i++){
	  int increment = 0; //the number of excess bytes
	  unsigned char next = input[i]; //next byte
	  unsigned char upper = next >> 4; //lower 4 bits
	  unsigned char lower = next & 15; //upper 4 bits
	  
	  //EOF test case
	  if(inputLength - i < 11){
		  int iterate = end(inputLength - i,next);
		  if(iterate == 1){
			  
			  //print .quad if there's only 8 bytes available, or just print .bytes
			  if(inputLength - i == 8){
				  fprintf(outputFile, "\r\n%016x: ",(unsigned int)currAddr);
				  printf("%016x: ",(unsigned int)currAddr);
				  fprintf(outputFile, ".quad   0x%02x%02x%02x%02x%02x%02x%02x%02x\n", input[i+7], input[i+6], input[i+5], input[i+4], input[i+3], input[i+2], input[i+1], input[i]);
				  printf(".quad   0x%02x%02x%02x%02x%02x%02x%02x%02x\n", input[i+7], input[i+6], input[i+5], input[i+4], input[i+3], input[i+2], input[i+1], input[i]);
			  } else {
				  for(int z = 0; z < inputLength - i; z++){
					 fprintf(outputFile, "\r\n%016x: ",(unsigned int)currAddr);
					 printf("%016x: ",(unsigned int)currAddr);
					 fprintf(outputFile, ".byte   0x%02x\n", input[i + z]);
					 printf(".byte   0x%02x\n", input[i + z]); 
					 currAddr += 1;
				  }
			  }
			  break;
		  }
	  }
	  
	  //Print the current address if the program is not in halt
	  if(upper != 0)
		  haltFlag = 0;
	  if(haltFlag == 0){
		  if(i == startAddress)
			fprintf(outputFile, "%016x: ",(unsigned int)currAddr);
		  else 
			fprintf(outputFile, "\r\n%016x: ",(unsigned int)currAddr);
		  printf("%016x: ",(unsigned int)currAddr);
	  }
	  
	  //determine the instruction operation from the upper four bits
	  switch(upper){
		  case 0: //halt
			if(lower == 0){
				if(haltFlag == 0){
					fprintf(outputFile,"00                    halt    \n");
					printf("00                    halt    \n");
					haltFlag = 1;
				}
				increment = 1;
			} else {
				increment = 8;
			}
			break;
		  case 1: //nop
			if(lower == 0){
				fprintf(outputFile, "10                    nop     \n");
				printf("10                    nop     \n");
				increment = 1;
			} else {
				increment = 8;
			}
			break;
		  case 2: //rrmovq, //cmovXX
			if(lower == 0)
				increment = rrmovq(input[i+1], outputFile);
			else {
				increment = cmovXX(input[i],input[i+1], outputFile);
			break;
		  case 3: //irmovq
		    if(lower == 0){
				increment = irmovq(input[i + 1], input[i], input [i+2], input[i+3], input[i+4], input[i+5], input[i+6], input[i+7], input[i+8], input[i+9], outputFile);
			} else
				increment = 8;
			break;
	      case 4: //rmmovq
			if(lower == 0)
				increment = rmmovq(input[i + 1], input[i], input [i+2], input[i+3], input[i+4], input[i+5], input[i+6], input[i+7], input[i+8], input[i + 9],outputFile);
			else 
				increment = 8;
			break;
		  case 5: //mrmovq
		    if(lower == 0)
				increment = mrmovq(input[i + 1], input[i], input [i+2], input[i+3], input[i+4], input[i+5], input[i+6], input[i+7], input[i+8], input[i+9], outputFile);
			else
				increment = 8;
			break;
		  case 6: //OPq
			increment = OPq(input[i], input[i+1], outputFile);
			break;
		  case 7: //jXX
			increment = jXX(input[i], input[i+1], input[i+2], input[i+3], input[i+4], input[i+5], input[i+6], input[i+7], input[i+8], outputFile);
			break;
	      case 8: //call
			if(lower == 0)
				increment = call(input[i], input[i+1], input[i+2], input[i+3], input[i+4], input[i+5], input[i+6], input[i+7], input[i+8], outputFile);
			else 
				increment = 8;
			break;
		  case 9: //ret
			if(lower == 0){
				fprintf(outputFile, "90                    ret      \n");
				printf("90                    ret     \n");
				increment = 1;
			} else {
				increment = 8;
			}
			break;
		  case 10: //pushq
			if(lower == 0)
				increment = pushq(input[i+1], outputFile);
			else 
				increment = 8;
			break;
		  case 11: //popq
			if(lower == 0)
				increment = popq(input[i+1], outputFile);
			else 
				increment = 8;
			break;
			
			//default print the .quad directive
		  default:
		    increment = 8;
		  }
	  }
	  
	  //If increment = 8 bytes, print the quad directive (no 8 byte instructions)
	 if(increment == 8){
		 
		 //Print the addresses of the quad if haltFlag is true
		if (haltFlag) {
		fprintf(outputFile, "\r\n%016x: ",(unsigned int)currAddr);
		 printf("%016x: ",(unsigned int)currAddr);
		}
		  unsigned long combinedAddr = ((long)input[i+7] << 56 | (long)input[i+6] << 48 | (long)input[i+5] << 40 | (long)input[i+4] << 32 | (long)input[i+3] << 24 | (long)input[i+2] << 16 | (long)input[i+1] << 8 | (long)input[i]);
		  fprintf(outputFile, ".quad   0x%0lx\n", combinedAddr);
		  printf(".quad   0x%0lx\n", combinedAddr);

	 }
	 
	  //iterate through the buffer and increment the current address counter
	  currAddr += increment;
	  i += increment - 1;
  }
  
  //Free the dynamic memory and close the scanners
  fclose(machineCode);
  fclose(outputFile);
  free(input);
  return SUCCESS;
}

//Function to print rrmovq instruction
int rrmovq (unsigned char ins, FILE *outputFile){
	int upper = ins >> 4;
	int lower = ins & 15;
	
	//Error in register bits, return 8 to print .quad directive
	if(upper > 0xe || lower > 0xe){
		return 8;
	}
	
	//Print the rrmovq function on a new line
	char * ra = getRegister(upper);
	char * rb = getRegister(lower); 
	 fprintf(outputFile, "20%02x                  rrmovq  %s, %s\n",ins,ra,rb);
	printf("20%02x                  rrmovq  %s, %s\n",ins,ra,rb);
	
	//free strings allocated on the heap from getRegister
	free(ra);
	free(rb);
	return 2;
}

//Function to determine if there's enough space is left at the end of the file to print an instruction
int end(int delta, unsigned char byte){
	int increment = 0; //number of bytes of instruction
	
	//switch statement to determine the number of bytes required for the instruction
	switch(byte){
		case 0:
		case 1:
		case 9: increment = 1;
				break;
		case 2:
		case 6:
		case 10:
		case 11: increment = 2;
				break;
		case 3:
		case 4:
		case 5: increment = 10;
				break;
		case 7:
		case 8: increment = 9;
	}
	
	//return true if there's not enough space
	if(increment > delta){
		return 1;
	}
	
	//return false if there is enough space
	return 0;
}

//Performs the cmov operation 
int cmovXX(unsigned char func, unsigned char ins, FILE *outputFile){
	//Gets the upper and lower bits for the ins byte
	int upper = ins >> 4;
	int lower = ins & 15;
	int funcLower = func & 15; //Gets the function lower bits
	
	//Checks to ensure that upper and lower bits are valid
	if(upper > 0xe || lower > 0xe){
		return 8;
	}
	if(funcLower > 6 || funcLower < 1){
		return 8;
	}
	char * op;
	//Statement to check for each operation
	switch(funcLower){
		case 1:
			op = "le"; //Less than equal
			break;
		case 2:
			op = "l "; //Less than
			break;
		case 3:
			op = "e "; //Equals
			break;
		case 4:
			op = "ne"; //Not equals
			break;
		case 5:
			op = "ge"; //Greater than equals
			break;
		case 6:
			op = "g "; //Greater than
			break;
	}
	//Gets the register names
	char * ra = getRegister(upper);
	char * rb = getRegister(lower);

	//Prints to console and saves to output file the instruction
	fprintf(outputFile, "%02x%02x                  cmov%s  %s, %s\n",func, ins, op,ra,rb);
	printf("%02x%02x                  cmov%s  %s, %s\n",func, ins, op,ra,rb);
	free(ra); //Frees to prevent memory leaks
	free(rb);
	
	return 2; //Returns the size of the instruction
}

//Prints and saves the output performed
int OPq(unsigned char func, unsigned char ins, FILE *outputFile){
	//Separates upper and lower bits
	int upper = ins >> 4;
	int lower = ins & 15;
	int funcLower = func & 15;
	
	//Checks for within operation bit bounds
	if(upper > 0xe || lower > 0xe){
		return 8;
	}
	if(funcLower > 6){
		return 8;
	}
	char * op;
	//Checks for each operation
	switch(funcLower){
		case 0:
			op = "addq"; //add 
			break;
		case 1:
			op = "subq"; //sub
			break;
		case 2:
			op = "andq"; //and
			break;
		case 3:
			op = "xorq"; //xor
			break;
		case 4:
			op = "mulq"; //multiply
			break;
		case 5:
			op = "divq"; //divide
			break;
		case 6:
			op = "modq"; //mod operator
			break;
	}
	//Gets the register names
	char * ra = getRegister(upper);
	char * rb = getRegister(lower);
	
	//Prints and saves the function instruction
	fprintf(outputFile, "%02x%02x                  %s    %s, %s\n",func,ins,op,ra,rb);
	printf("%02x%02x                  %s    %s, %s\n",func,ins,op,ra,rb);
	free(ra); //Frees to prevent memory leak
	free(rb);
	
	return 2; //Returns the number of bytes used
}

//Performs the rmmovq instruction
int rmmovq(unsigned char ins, unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4, unsigned char v5, unsigned char v6, unsigned char v7, unsigned char v8, unsigned char v9, FILE *outputFile) {
    //Separates the upper and lower bits
	int lower = ins & 15;
	int upper = ins >> 4;
	//Checks for bounds
	if (upper > 0xe || lower > 0xe){
			return 8; //Returns that operation was skipped
	}
	//Gets the register names
	char *ra = getRegister(upper);
	char *rb = getRegister(lower);
	//Combines the hex addresses into one variable
	unsigned long combinedAddr = ((long)v9 << 56 | (long)v8 << 48 | (long)v7 << 40 | (long)v6 << 32 | (long)v5 << 24 | (long)v4 << 16 | (long)v3 << 8 | (long)v2);
	//Prints and saves the output
	fprintf(outputFile, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  rmmovq  %s, $0x%0lx(%s)\n", v1, ins, v2, v3, v4, v5, v6, v7, v8, v9, ra, combinedAddr, rb);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  rmmovq  %s, $0x%0lx(%s)\n", v1, ins, v2, v3, v4, v5, v6, v7, v8, v9, ra, combinedAddr, rb);
	free(rb); //Frees to prevent memory leaks
	free(ra);
	
	return 10; //Returns number of bytes used
}

//Performs the mrmovq instruction
int mrmovq(unsigned char ins, unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4, unsigned char v5, unsigned char v6, unsigned char v7, unsigned char v8, unsigned char v9, FILE *outputFile) {
	//Separates the upper and lower bytes
	int lower = ins & 15;
	int upper = ins >> 4;
	//Checks for the operation bit bounds
	if (upper > 0xe || lower > 0xe){ 
			return 8; //Returns that the operation was skipped
	}
	//Gets the register names
	char *ra = getRegister(upper);
	char *rb = getRegister(lower);
	//Combines the hex addresses into one variable
	unsigned long combinedAddr = ((long)v9 << 56 | (long)v8 << 48 | (long)v7 << 40 | (long)v6 << 32 | (long)v5 << 24 | (long)v4 << 16 | (long)v3 << 8 | (long)v2);
	//Prints and saves the output
	fprintf(outputFile, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  mrmovq  $0x%0lx(%s), %s\n", v1, ins, v2, v3, v4, v5, v6, v7, v8, v9, combinedAddr, rb,ra);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  mrmovq  $0x%0lx(%s), %s\n", v1, ins, v2, v3, v4, v5, v6, v7, v8, v9, combinedAddr, rb,ra);
	free(ra); //Frees to prevent memory leaks
	free(rb);
	
	return 10; //Returns the number of bytes used
}

//Prints the irmovq instruction
int irmovq(unsigned char ins, unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4, unsigned char v5, unsigned char v6, unsigned char v7, unsigned char v8, unsigned char v9, FILE *outputFile) {
	//Separates the upper and lower instruction bits
	int lower = ins & 15;
	int upper = ins >> 4;
	//Checks for the operation bit bounds
	if (upper != 0xf || lower > 0xe){
			return 8;
	}
	//Gets the register for the operation
	char *rb = getRegister(lower);
	//Combines the hex addresses into one variable
	unsigned long combinedAddr = ((long)v9 << 56 | (long)v8 << 48 | (long)v7 << 40 | (long)v6 << 32 | (long)v5 << 24 | (long)v4 << 16 | (long)v3 << 8 | (long)v2);
	//Prints and saves the output
	fprintf(outputFile, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  irmovq  $0x%0lx, %s\n", v1, ins, v2, v3, v4, v5, v6, v7, v8, v9, combinedAddr, rb);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  irmovq  $0x%0lx, %s\n", v1, ins, v2, v3, v4, v5, v6, v7, v8, v9, combinedAddr, rb);
	free(rb); //Frees the pointer
	
	return 10; //Returns the number of bytes used
}

//Prints the jXX instruction
int jXX(unsigned char ins, unsigned char d2, unsigned char d3, unsigned char d4, unsigned char d5, unsigned char d6, unsigned char d7, unsigned char d8, unsigned char d9, FILE *outputFile) {
	//Separates the upper and lower instruction bits
	 int upper = ins >> 4;
	int lower = ins & 15;
	//Checks for the operation bit bounds
	if (upper != 0x7 || lower > 0x6){
			return 8; //Returns that instruction was skipped
	}
	char *op;
	//Checks the operation used
	switch(lower) {
			case 0:
					op = "mp";
					break;
			case 1:
					op = "le";
					break;
			case 2:
					op = "l ";
					break;
			case 3:
					op = "e ";
					break;
			case 4:
					op = "ne";
					break;
			case 5:
					op = "ge";
					break;
			case 6:
					op = "g ";
					break;
	}
	//Combines the hex addresses into one variable
	unsigned long combinedAddr = ((long)d9 << 56 | (long)d8 << 48 | (long)d7 << 40 | (long)d6 << 32 | (long)d5 << 24 | (long)d4 << 16 | (long)d3 << 8 | (long)d2);
	//Prints and saves the output file
	fprintf(outputFile, "%02x%02x%02x%02x%02x%02x%02x%02x%02x    j%s     0x%0lx\n", ins, d2, d3, d4, d5, d6, d7, d8, d9, op, combinedAddr);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x    j%s     0x%0lx\n", ins, d2, d3, d4, d5, d6, d7, d8, d9, op, combinedAddr);
	
	return 9; //Returns number of bytes used
}

//Prints the call instruction
int call(unsigned char ins, unsigned char d2, unsigned char d3, unsigned char d4, unsigned char d5, unsigned char d6, unsigned char d7, unsigned char d8, unsigned char d9, FILE *outputFile) {
	//Separates the upper and lower bits
	int upper = ins >> 4;
	int lower = ins & 15;
	//Checks for instruction bit bounds
	if (upper != 0x8 || lower != 0x0){
			return 8;
	}
	//Combines the hex addresses into one variable
	unsigned long combinedAddr = ((long)d9 << 56 | (long)d8 << 48 | (long)d7 << 40 | (long)d6 << 32 | (long)d5 << 24 | (long)d4 << 16 | (long)d3 << 8 | (long)d2);
	//Prints and saves the instruction
	fprintf(outputFile, "%02x%02x%02x%02x%02x%02x%02x%02x%02x    call    0x%0lx\n", ins, d2, d3, d4, d5, d6, d7, d8, d9, combinedAddr);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x    call    0x%0lx\n", ins, d2, d3, d4, d5, d6, d7, d8, d9, combinedAddr);

	return 9; //Returns number of bytes used
}

//Prints the push instruction
int pushq (unsigned char ins, FILE *outputFile){
	//Separates the upper and lower bits
	int upper = ins >> 4;
	int lower = ins & 15;
	//Checks for instruction bit bounds
	if(upper > 0xe || lower != 0xf){
		return 8;
	}
	//Gets the register name
	char * ra = getRegister(upper);
	//Prints and saves the instruction
	fprintf(outputFile, "a0%02x                  pushq   %s\n",ins,ra);
	printf("a0%02x                  pushq   %s\n",ins,ra);
	free(ra);
	return 2;
}

//Prints the pop instruction
int popq (unsigned char ins, FILE *outputFile){
	//Separates the upper and lower bits
	int upper = ins >> 4;
	int lower = ins & 15;
	//Checks for instruction bit bounds
	if(upper > 0xe || lower != 0xf){
		return 8;
	}
	//Gets the register name
	char * ra = getRegister(upper);
	//Prints and saves the instruction
	 fprintf(outputFile, "b0%02x                  popq    %s\n",ins, ra);
	printf("b0%02x                  popq    %s\n",ins, ra);
	free(ra);
	
	return 2; //Returns number of bytes used
}

//Gets the register name
char * getRegister(unsigned char reg){
	char * regName = malloc(10);
	unsigned char next;
	unsigned char ra;
	//Sets the register to look at
	next = reg;
	//Get lower 4 bytes
	ra = next & 15;
	//Switch statement to get the regName
	switch(ra){
		case 0: 
		  strcpy(regName,"%rax");
		  break;
		case 1:
		  strcpy(regName,"%rcx");
		  break;
		case 2: 
		  strcpy(regName,"%rdx");
		  break;
		case 3:
		  strcpy(regName,"%rbx");
		  break;
		case 4: 
		  strcpy(regName,"%rsp");
		  break;
		case 5:
		  strcpy(regName,"%rbp");
		  break;
		case 6: 
		  strcpy(regName,"%rsi");
		  break;
		case 7:
		  strcpy(regName,"%rdi");
		  break;
		case 8: 
		  strcpy(regName,"%r8 ");
		  break;
		case 9:
		  strcpy(regName,"%r9 ");
		  break;
		case 10: 
		  strcpy(regName,"%r10");
		  break;
		case 11:
		  strcpy(regName,"%r11");
		  break;
		case 12:
		  strcpy(regName,"%r12");
		  break;
		case 13: 
		  strcpy(regName,"%r13");
		  break;
		case 14:
		  strcpy(regName,"%r14");
		  break;
		default: strcpy(regName, "err"); //Error not found register
	}
	
	return regName; //Returns the found register name
}

//Gets the first non-zero index of array
int getStartIndex(unsigned char *input) {
	int index = 0;
	
	//Iterates while its not equal to 0
	while (input[index] == 0) {
		index++;
	}
	//Returns the first non-zero index
	return index; 
}

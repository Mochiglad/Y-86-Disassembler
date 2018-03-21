/* This file contains the prototypes and constants needed to use the
   routines defined in printRoutines.c
*/

#ifndef _PRINTROUTINES_H_
#define _PRINTROUTINES_H_

#include <stdio.h>

int samplePrint(FILE *);
int rrmovq (unsigned char ins, FILE *outputFile);
int cmovXX(unsigned char func, unsigned char ins, FILE *outputFile);
int irmovq(unsigned char ins, unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4, unsigned char v5, unsigned char v6, unsigned char v7, unsigned char v8, unsigned char v9, FILE *outputFile);
int rmmovq(unsigned char ins, unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4, unsigned char v5, unsigned char v6, unsigned char v7, unsigned char v8, unsigned char v9, FILE *outputFile);
int mrmovq(unsigned char ins, unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4, unsigned char v5, unsigned char v6, unsigned char v7, unsigned char v8, unsigned char v9, FILE *outputFile);
int jXX(unsigned char ins, unsigned char d2, unsigned char d3, unsigned char d4, unsigned char d5, unsigned char d6, unsigned char d7, unsigned char d8, unsigned char d9, FILE *outputFile);
int call(unsigned char ins, unsigned char d2, unsigned char d3, unsigned char d4, unsigned char d5, unsigned char d6, unsigned char d7, unsigned char d8, unsigned char d9, FILE *outputFile);
int OPq(unsigned char func, unsigned char ins, FILE *outputFile);
int pushq(unsigned char ins, FILE *outputFile);
int popq(unsigned char ins, FILE *outputFile);
char *getRegister(unsigned char reg);
int getStartIndex(unsigned char *input);
int end(int delta, unsigned char byte);
#endif /* PRINTROUTINES */

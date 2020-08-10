#pragma once
#include"miracl.h"
#include"mirdef.h"

extern miracl* mip;
extern int Max;

big SM3(big);
char* SM3ByHexStr(char*);

void  bTd(int *a, int length);
void CF(unsigned int *V, big B);

unsigned int Rol(unsigned int n, int m);
unsigned int P0(unsigned int TT2);
unsigned int P1(unsigned m);
unsigned int TT(int j);
unsigned int FF(int i, unsigned int a, unsigned int b, unsigned int c);
unsigned int GG(int i, unsigned int a, unsigned int b, unsigned int c);


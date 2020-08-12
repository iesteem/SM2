/*
big运算；epoint运算
*/
#pragma once
#include"String.h"
#include<stdlib.h>
#include"miracl.h"
#include"mirdef.h"

extern miracl *mip;
extern int Max;

/*
椭圆曲线点运算
*/
epoint* NewPoint(big x, big y);
epoint* AddEpoint(epoint*, epoint*);
epoint* MultiplyEpoint(big, epoint*);
big PointX(epoint*);
big PointY(epoint*);
String* EpointToBytes(epoint *);  //字符串结构首字节为04h

/*
大数运算
*/
big Xor2(big x, big y);        // x ^ y（异或）
big And2(big x, big y);        // x & y（与）
big Add2(big x, big y);        // x + y 
big Sub2(big x, big y);        // x - y 
big Multiply2(big x, big y);   // x * y 
big Divide2(big x, big y);     // x / y 
big Mod2(big x, big y);        // x % y 
big Mod(big x, big y, big z);  // x的y次方，再取余z
big Pow2(big x, int y);	       // x ^ y(幂次)

/*
其他运算
*/

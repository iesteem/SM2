/*
big���㣻epoint����
*/
#pragma once
#include"String.h"
#include<stdlib.h>
#include"miracl.h"
#include"mirdef.h"

extern miracl *mip;
extern int Max;

/*
��Բ���ߵ�����
*/
epoint* NewPoint(big x, big y);
epoint* AddEpoint(epoint*, epoint*);
epoint* MultiplyEpoint(big, epoint*);
big PointX(epoint*);
big PointY(epoint*);
String* EpointToBytes(epoint *);  //�ַ����ṹ���ֽ�Ϊ04h

/*
��������
*/
big Xor2(big x, big y);        // x ^ y�����
big And2(big x, big y);        // x & y���룩
big Add2(big x, big y);        // x + y 
big Sub2(big x, big y);        // x - y 
big Multiply2(big x, big y);   // x * y 
big Divide2(big x, big y);     // x / y 
big Mod2(big x, big y);        // x % y 
big Mod(big x, big y, big z);  // x��y�η�����ȡ��z
big Pow2(big x, int y);	       // x ^ y(�ݴ�)

/*
��������
*/

#pragma once
#include<stdlib.h>
#include"miracl.h"
#include"mirdef.h"

extern miracl *mip;
extern int Max;

/*
带有长度size的unsigned char数组(字节数组)
*/
typedef struct String
{
	unsigned char* data;
	int size;
}String;

/*
形式转换
*/
char* ConvertStringAsHex(String*);      //字符串结构转十六进制串
char* GetPartHexStr(char*, int, int);	//截取十六进制串
char* BigToHexChars2(big x);            //大数转十六进制串
big HexCharsToBig(char*);               //十六进制串转大数
//int big_to_bytes(int,big,char*,bool):大数转字符串，返回字符串长度
//String* EpointToBytes(epoint *);椭圆曲线点转字符串
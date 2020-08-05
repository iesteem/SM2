#define  _CRT_SECURE_NO_WARNINGS
#include"String.h"
#include<stdio.h>
#include<stdlib.h>

/*
字符串结构转十六进制串
*/
char* ConvertStringAsHex(String* s)
{
	char* result = (char*)malloc(sizeof(char)*(s->size * 2 + 1));  //字符串结构转十六进制串(一个字符占一个字节，一个十六进制数占半个字节)
	for (int i = 0; i < s->size; i++)  //遍历字符串结构
	{
		sprintf(&result[i * 2], "%02x", s->data[i]);  //数组s的内容以十六进制形式转存到数组result
	}
	result[s->size * 2] = '\0';  //数组result的最后一个元素标识字符串结束
	return result;
}

/*
截取选定的十六进制串
*/
char* GetPartHexStr(char* string, int startIndex, int length)
{
	char* str = (char*)malloc(sizeof(char)*(length + 1));

	int i = 0;
	for (int j = 0; j < length; j++)
	{
		str[i++] = string[startIndex + j];
	}
	str[i] = '\0';
	return str;
}

/*
 大数转十六进制串
*/
char* BigToHexChars2(big x)
{
	mip->IOBASE = 16;  //字符串设定为十六进制
	char *str = (char*)malloc(sizeof(char)*Max);
	cotstr(x, str);  //将大数转换成十六进制串
	return str;
}

/*
十六进制串转换为大数
*/
big HexCharsToBig(char* str)
{
	mip->IOBASE = 16;
	big result = mirvar(0);
	cinstr(result, str);
	return result;
}
#define  _CRT_SECURE_NO_WARNINGS
#include"String.h"
#include<stdio.h>
#include<stdlib.h>

/*
�ַ����ṹתʮ�����ƴ�
*/
char* ConvertStringAsHex(String* s)
{
	char* result = (char*)malloc(sizeof(char)*(s->size * 2 + 1));  //�ַ����ṹתʮ�����ƴ�(һ���ַ�ռһ���ֽڣ�һ��ʮ��������ռ����ֽ�)
	for (int i = 0; i < s->size; i++)  //�����ַ����ṹ
	{
		sprintf(&result[i * 2], "%02x", s->data[i]);  //����s��������ʮ��������ʽת�浽����result
	}
	result[s->size * 2] = '\0';  //����result�����һ��Ԫ�ر�ʶ�ַ�������
	return result;
}

/*
��ȡѡ����ʮ�����ƴ�
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
 ����תʮ�����ƴ�
*/
char* BigToHexChars2(big x)
{
	mip->IOBASE = 16;  //�ַ����趨Ϊʮ������
	char *str = (char*)malloc(sizeof(char)*Max);
	cotstr(x, str);  //������ת����ʮ�����ƴ�
	return str;
}

/*
ʮ�����ƴ�ת��Ϊ����
*/
big HexCharsToBig(char* str)
{
	mip->IOBASE = 16;
	big result = mirvar(0);
	cinstr(result, str);
	return result;
}
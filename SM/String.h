#pragma once
#include<stdlib.h>
#include"miracl.h"
#include"mirdef.h"

extern miracl *mip;
extern int Max;

/*
���г���size��unsigned char����(�ֽ�����)
*/
typedef struct String
{
	unsigned char* data;
	int size;
}String;

/*
��ʽת��
*/
char* ConvertStringAsHex(String*);      //�ַ����ṹתʮ�����ƴ�
char* GetPartHexStr(char*, int, int);	//��ȡʮ�����ƴ�
big HexCharsToBig(char*);               //ʮ�����ƴ�ת����
char* BigToHexChars2(big x);            //����תʮ�����ƴ�
//int big_to_bytes(int,big,char*,bool);   ����ת�ַ����������ַ�������
//String* EpointToBytes(epoint *);        ��Բ���ߵ�ת�ַ������
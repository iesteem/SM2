#define _CRT_SECURE_NO_WARNINGS
#include<stdlib.h>
#include<Windows.h>
#include"miracl.h"
#include"mirdef.h"
#include"Sm2.h"
#include"String.h"

int Max = 1200;
miracl *mip;

big k;								//�����

big PBx;							//B��Կx
big PBy;							//B��Կy
big DB;								//B˽Կ

int lengthC1x;						//C1��x����
int lengthC1y;						//C1��y����
int lengthC1 = 130;                 //C1��ʮ�����ƴ�����
int lengthC3 = 64;					//C3��ʮ�����ƴ�����
char* ccode;						//���ܵõ�������

char* signature;                    //ǩ����Ϣ
int lengthRS = 64;                  //ǩ���� r��s ��ʮ�����ƴ�����

char *inputFileName = "input.txt";	//�����ļ���
String fileData;					//�����ļ�����

int main()
{
	mip = mirsys(500, Max);
	ecurve_init(HexCharsToBig(a), HexCharsToBig(b), HexCharsToBig(p), MR_PROJECTIVE);	//��ʼ����Բ�����ڲ�����
	Encryption();
	Decryption();

	MakeSign();
	VerifySign();

	system("pause");
	return 0;
}
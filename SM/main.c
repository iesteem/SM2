#define _CRT_SECURE_NO_WARNINGS
#include<stdlib.h>
#include<Windows.h>
#include"miracl.h"
#include"mirdef.h"
#include"Sm2.h"
#include"String.h"

int Max = 6000;
miracl *mip;

big k;								//�����

big PBx;							//B��Կx
big PBy;							//B��Կy
big DB;								//B˽Կ
big PAx;							//A��Կx
big PAy;							//A��Կy
big DA;								//A˽Կ

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
	mip = mirsys(Max, 16);
	ecurve_init(HexCharsToBig(a), HexCharsToBig(b), HexCharsToBig(p), MR_PROJECTIVE);	//��ʼ����Բ�����ڲ�����

	Encryption();
	Decryption();


	/*  ֱ�Ӽ��input�ļ��е��ַ����ݵ�SM3ժҪ
	ReadInputFile();
	printf("�����ַ�����Ϊ:\n%s\n\n", fileData.data);  //����������ȷ
	printf("�����ַ�����Ϊ:\n%d\n\n", fileData.size);  //���������ȷ

	char* sm3 = (char*)malloc(sizeof(char)*(fileData.size * 2 + 1));  //ʮ�����Ƹ���
	int i = 0;
	for (int j = 0; j < fileData.size; j++)
	{
		sprintf(&sm3[i], "%02x", (unsigned char)(fileData.data[j]));
		i += 2;
	}
	sm3[i] = '\0';
	printf("����ʮ�����ƴ�����Ϊ:\n%s\n\n", sm3);  //ת��Ϊʮ�����ƴ���ȷ
	sm3 = SM3ByHexStr(sm3);
	printf("ǩ��:\n%s\n\n", sm3);
	*/

	MakeSign();
	VerifySign();

	ExchangeKey();

	system("pause");
	return 0;
}
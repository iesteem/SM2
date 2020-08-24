#define _CRT_SECURE_NO_WARNINGS
#include<stdlib.h>
#include<Windows.h>
#include"miracl.h"
#include"mirdef.h"
#include"Sm2.h"
#include"String.h"

int Max = 6000;
miracl *mip;

big k;								//随机数

big PBx;							//B公钥x
big PBy;							//B公钥y
big DB;								//B私钥
big PAx;							//A公钥x
big PAy;							//A公钥y
big DA;								//A私钥

int lengthC1x;						//C1的x长度
int lengthC1y;						//C1的y长度
int lengthC1 = 130;                 //C1的十六进制串长度
int lengthC3 = 64;					//C3的十六进制串长度
char* ccode;						//加密得到的密文

char* signature;                    //签名信息
int lengthRS = 64;                  //签名中 r与s 的十六进制串长度

char *inputFileName = "input.txt";	//输入文件名
String fileData;					//输入文件数据

int main()
{
	mip = mirsys(Max, 16);
	ecurve_init(HexCharsToBig(a), HexCharsToBig(b), HexCharsToBig(p), MR_PROJECTIVE);	//初始化椭圆曲线内部参数

	Encryption();
	Decryption();


	/*  直接检查input文件中的字符数据的SM3摘要
	ReadInputFile();
	printf("输入字符数据为:\n%s\n\n", fileData.data);  //读入数据正确
	printf("输入字符个数为:\n%d\n\n", fileData.size);  //读入个数正确

	char* sm3 = (char*)malloc(sizeof(char)*(fileData.size * 2 + 1));  //十六进制个数
	int i = 0;
	for (int j = 0; j < fileData.size; j++)
	{
		sprintf(&sm3[i], "%02x", (unsigned char)(fileData.data[j]));
		i += 2;
	}
	sm3[i] = '\0';
	printf("输入十六进制串数据为:\n%s\n\n", sm3);  //转化为十六进制串正确
	sm3 = SM3ByHexStr(sm3);
	printf("签名:\n%s\n\n", sm3);
	*/

	MakeSign();
	VerifySign();

	ExchangeKey();

	system("pause");
	return 0;
}
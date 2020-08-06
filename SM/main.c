#define _CRT_SECURE_NO_WARNINGS
#include<stdlib.h>
#include<Windows.h>
#include"miracl.h"
#include"mirdef.h"
#include"Sm2.h"
#include"String.h"

int Max = 1200;
miracl *mip;

big k;								//随机数

big PBx;							//B公钥x
big PBy;							//B公钥y
big DB;								//B私钥

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
	mip = mirsys(500, Max);
	ecurve_init(HexCharsToBig(a), HexCharsToBig(b), HexCharsToBig(p), MR_PROJECTIVE);	//初始化椭圆曲线内部参数
	Encryption();
	Decryption();

	MakeSign();
	VerifySign();

	system("pause");
	return 0;
}
#pragma once
#include"String.h"
#include"miracl.h"
#include"mirdef.h"
#include"Sm3.h"
#include"Operation.h"

/*
定义外部导入
*/
extern miracl *mip;
extern int Max;

extern big k;						//随机数k，来自InitRandomK()

extern big PBx;						//公钥x，来自CalculateBKeys()
extern big PBy;						//公钥y，来自CalculateBKeys()
extern big DB;						//私钥 ，来自CalculateBKeys()	
extern big PAx;						//公钥x，来自CalculateAKeys()
extern big PAy;						//公钥y，来自CalculateAKeys()
extern big DA;						//私钥 ，来自CalculateAKeys()			

extern char* p;						//给定参数
extern char* a;						//给定参数
extern char* b;						//给定参数
extern char* n;						//给定参数
extern char* Gx;					//给定参数
extern char* Gy;					//给定参数

extern char* ID;					//给定参数
extern char* ENTL;					//给定参数

extern int lengthC1x;				//C1的x长度
extern int lengthC1y;				//C1的y长度

extern int lengthC1;                //C1的十六进制串长度
extern int lengthC3;				//C3的十六进制串长度

extern char *inputFileName;			//输入文件名
extern String fileData;				//输入文件数据

extern char* ccode;					//加密得到的密文
extern char* signature;             //签名信息

extern int lengthRS;                //签名中 r与s 的十六进制串长度

/*
功能函数声明
*/
big GetBigRandom(big, big);		        //产生随机数 a<= result <=b
void InitRandomK();					    //产生随机参数K
void CalculateBKeys();				    //产生公钥和私钥
int VerifyKeys(big x, big y);			//验证公钥和私钥
void CalculateAKeys();				    //产生公钥和私钥
epoint *CalculateG();				    //自定义参数G
epoint *CalculatePB();				    //公钥PB(PBx,PBy)
epoint *CalculatePA();				    //公钥PA(PAx,PAy)
void ReadInputFile();				    //读取文件输入

void Encryption();					    //加密
epoint *CalculatePoint1();			    //计算(x1,y1)
epoint *CalculatePoint2();			    //计算(x2,y2)
char *CalculateC1();				    //计算C1
String *CalculateC2();				    //计算C2
char* CalculateC3();				    //计算C3
big KDF(epoint*, int);				    //计算t
void Decryption();					    //解密

void MakeSign();                        //制作签名
void VerifySign();                      //验证签名
big CalculateE();                       //计算e

void ExchangeKey();                     //密钥交换
epoint *CalculatePointR(big r);         //计算R
big CalculateXX(big x);				    //计算xx
big CalculateT(big d, big xx, big r);   //计算t
epoint *CalculateU(big t, epoint *P, big x, epoint *R);   //计算t
char* CalculateZ(char* ENTL, char* ID,
	  char* pointX, char* pointY);                        //计算Z
big CalculateK(big x, big y, char* ZA, char* ZB);         //计算K
char* CalculateH(char* ux, char* ZA, char* ZB,
	  char* x1, char* y1, char* x2, char* y2);            //计算H
char* CalculateS(char* m, char* ux, char* h);             //计算S
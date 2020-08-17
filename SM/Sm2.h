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

extern big PBx;						//B公钥x
extern big PBy;						//B公钥y
extern big DB;						//B私钥 	
extern big PAx;						//A公钥x
extern big PAy;						//A公钥y
extern big DA;						//A私钥		

extern char* p;						//椭圆曲线参数
extern char* a;						//
extern char* b;						//
extern char* n;						//
extern char* Gx;					//
extern char* Gy;					//

extern char* ID;					//用户默认参数
extern char* ENTL;					//

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
void Decryption();					    //解密
epoint *CalculatePoint1();			    //计算(x1,y1)
epoint *CalculatePoint2();			    //计算(x2,y2)
char *CalculateC1();				    //计算C1
String *CalculateC2();				    //计算C2
char* CalculateC3();				    //计算C3
big KDF(epoint*, int);				    //计算t

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
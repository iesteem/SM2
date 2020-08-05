#pragma once
#include"String.h"
#include"miracl.h"
#include"mirdef.h"
#include"Sm3.h"
#include"Operation.h"

/*
�����ⲿ����
*/
extern miracl *mip;
extern int Max;

extern big k;						//�����k������InitRandomK()

extern big PBx;						//��Կx������CalculateBKeys()
extern big PBy;						//��Կy������CalculateBKeys()
extern big DB;						//˽Կ������CalculateBKeys()							

extern char* p;						//��������
extern char* a;						//��������
extern char* b;						//��������
extern char* n;						//��������
extern char* Gx;					//��������
extern char* Gy;					//��������

extern char* ID;					//��������
extern char* ENTL;					//��������

extern int lengthC1x;				//C1��x����
extern int lengthC1y;				//C1��y����

extern int lengthC1;                //C1��ʮ�����ƴ�����
extern int lengthC3;				//C3��ʮ�����ƴ�����

extern char *inputFileName;			//�����ļ���
extern String fileData;				//�����ļ�����

extern char* ccode;					//���ܵõ�������
extern char* signature;             //ǩ����Ϣ

extern int lengthRS;                //ǩ���� r��s ��ʮ�����ƴ�����

/*
���ܺ�������
*/
big GetBigRandom(big, big);		        //��������� a<= result <=b
void InitRandomK();					    //�����������K
void CalculateBKeys();				    //������Կ��˽Կ
int VerifyBKeys();					    //��֤��Կ��˽Կ
epoint *CalculateG();				    //�Զ������G
epoint *CalculatePB();				    //��ԿPB(PBx,PBy)
void ReadInputFile();				    //��ȡ�ļ�����

void Encryption();					    //����
epoint *CalculatePoint1();			    //����(x1,y1)
epoint *CalculatePoint2();			    //����(x2,y2)
char *CalculateC1();				    //����C1
String *CalculateC2();				    //����C2
char* CalculateC3();				    //����C3
big KDF(epoint*, int);				    //����t
void Decryption();					    //����


void MakeSign();                        //����ǩ��
void VerifySign();                      //��֤ǩ��
big CalculateE();                       //����e
big CalculateR();                       //����r
big CalculateS();                       //����s
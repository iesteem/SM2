 #define _CRT_SECURE_NO_WARNINGS
#include"Sm2.h"
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
#include"Operation.h"
#include"miracl.h"
#include"mirdef.h"
#include"String.h"
#include"Sm3.h"

/*
���������������ʮ�����ƴ���ʾ
*/
char* p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
char* a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
char* b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
char* n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
char* Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
char* Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
char* ID = "31323334353637383132333435363738";    //Ĭ��ID
char* ENTL = "0080";                              //Ĭ��ENTL

/***********************************
*****************����***************
ע�ͣ��������ܹ���ʹ��ͬһ�������k
***********************************/
void Encryption()
{
	CalculateBKeys();		//������Կ��˽Կ
	VerifyKeys(PBx,PBy);	//��֤��Կ��˽Կ
	ReadInputFile();        //��ȡ�ļ�����

Restart:				//���¿�ʼ���ɲ���
	InitRandomK();			//��ʼ�������

	//C1��C3, ʮ�����ƴ�
	char* c1String = CalculateC1();
	char* c3String = CalculateC3();


	//C2�����ַ�����ʽת����ʮ�����ƴ�
	String *C2 = CalculateC2();
	if (C2->size <= 0 && C2->data == NULL)	//tȫ��
	{
		goto Restart;
	}
	char* c2String = ConvertStringAsHex(C2);
	free(C2->data);
	free(C2);

	//��ӡ������Ҫ����
	printf("***************��Բ���߷���Ϊ��y^2=x^3+a*x+b\n");
	printf("p=%s\n", p);
	printf("a=%s\n", a);
	printf("b=%s\n", b);
	printf("n=%s\n", n);
	printf("Gx=%s\n", Gx);
	printf("Gy=%s\n", Gy);
	printf("k=%s\n\n", BigToHexChars2(k));
	printf("***************��Կ��������****************\n");
	printf("˽Կ=%s\n\n", BigToHexChars2(DB));
	printf("��Կx=%s\n\n", BigToHexChars2(PBx));
	printf("��Կy=%s\n\n", BigToHexChars2(PBy));
	printf("***************�����м���������************\n");
	printf("C1=%s\n", c1String);
	printf("C3=%s\n", c3String);
	printf("C2=%s\n", c2String);
	

	/*
	ƴ���ַ���
	*/
	char *c = (char*)calloc(strlen(c1String) + strlen(c2String) + strlen(c3String) + 1, sizeof(char));  //����ʮ�����ƴ������ڴ�
	strcat(c, c1String);  //strcatƴ��ʱ��c1String�Ḳ��c����\0������c1String����\0
	strcat(c, c3String);
	strcat(c, c2String);
	free(c1String); 
	free(c3String);
	free(c2String);
	ccode = c;  

	printf("����:\n%s\n\n", fileData.data);  //��������
	printf("���ģ�\n%s\n\n\n", ccode);       //��������
}


/*********************************
**************����****************
ע�ͣ����漰�����k
*********************************/
void Decryption()
{
    
	/*
	��֤ʮ�����ƴ�C1�Ƿ�������Բ���߷���
	*/
	char* x1String = GetPartHexStr(ccode, 2, lengthC1x);  //�ַ�����4��ʮ�����ƴ��б�ʾΪ ��04��
	char* y1String = GetPartHexStr(ccode, 2 + lengthC1x, lengthC1y);
	big C1x = mirvar(0);
	big C1y = mirvar(0);
	C1x = HexCharsToBig(x1String);
	C1y = HexCharsToBig(y1String);
	if (!compare(Mod2(Pow2(C1y, 2), HexCharsToBig(p)), Mod2(Add2(Pow2(C1x, 3), Add2(Multiply2(C1x, HexCharsToBig(a)), HexCharsToBig(b))), HexCharsToBig(p))))		// if((PBy^2 %p) != ((PBx^3 + a*PBx +b)%p))
	{
		printf("C1��֤��Ч������������\n");
		system("pause");
		exit(1);
	}

	/*
	��Բ���ߵ�C1��C2
	*/
	epoint* C1 = NewPoint(HexCharsToBig(x1String), HexCharsToBig(y1String));
	epoint* C2 = MultiplyEpoint(DB, C1);	//��� [DB]C1=(x2, y2)
	epoint_free(C1);

	/*
	�������
	*/
	char* C1String = GetPartHexStr(ccode, 0, lengthC1);
	char* C3String = GetPartHexStr(ccode, lengthC1, lengthC3);
	char* C2String = GetPartHexStr(ccode, lengthC1 + lengthC3, strlen(ccode)-lengthC1 - lengthC3);
	//printf("C1=%s\n\n", C1String);
	//printf("C3=%s\n\n", C3String);
	//printf("C2=%s\n\n", C2String);

	
	/*
	����t����
	*/
	int klen = strlen(C2String) / 2;        //�������ݵ��ַ�����
	big t = KDF(C2, klen);					//��� t = KDF(x2��y2,klen)
	if (compare(t, mirvar(0)) == 0)
	{
		printf("����ʱtȫ0������\n");
		system("pause");
		exit(3);
	}

	/*
	���M'
	*/
	big C2Number = mirvar(0);
	C2Number = HexCharsToBig(C2String);
    char* mcode = BigToHexChars2(Xor2(C2Number, t));  
	mirkill(C2Number);
	
	/*
	ƴ��ʮ�����ƴ���xmy = x2  ||  M'  ||  Y2
	*/
	char* xmy = (char*)calloc(strlen(BigToHexChars2(PointX(C2))) + strlen(BigToHexChars2(PointY(C2))) + strlen(mcode) + 1, sizeof(char));
	strcat(xmy, BigToHexChars2(PointX(C2)));
	strcat(xmy, mcode);
	strcat(xmy, BigToHexChars2(PointY(C2)));

	/*
	�Ƚ�u��C3
	*/
	if (strcmp(SM3ByHexStr(xmy), C3String) != 0)
	{
		printf("����ʧ��\n");
		return;
	}
	free(xmy);

	printf("����֤�����ܳɹ�������ʮ�����ƴ�Ϊ:\n%s\n", mcode);


	/*
	���������ַ�����ʽ���
	*/
	big mNumber = mirvar(0);
	mNumber = HexCharsToBig(mcode);
	char mString[1000];
	int mStringLength = big_to_bytes(0, mNumber, mString, FALSE);  //����ת�����ַ���
	mString[mStringLength] = '\0';  //��\0
	printf("���������Ϊ:\n%s\n\n", mString);
}



/***********************************
��������� a<= result <=b
***********************************/
big GetBigRandom(big a, big b)
{
	irand((unsigned)time(NULL));
	//irand("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
	big result = mirvar(0);
	bigrand(Add2(Sub2(b, a), mirvar(1)), result);		// 0<= result <b-a+1
	return Add2(result, a);							// a<= xxx <=b
}

/***********************************
�����������K
ע�ͣ��������������ȫ�ֱ���k
***********************************/
void InitRandomK()
{
    k = mirvar(0);
	copy(GetBigRandom(mirvar(1), Sub2(HexCharsToBig(n), mirvar(1))), k);	// 1<= k <= n-1
}

/***********************
����G
***********************/
epoint * CalculateG()
{
	epoint *G = (epoint*)malloc(sizeof(epoint));
	G = epoint_init();
	epoint_set(HexCharsToBig(Gx), HexCharsToBig(Gy), 0, G);
	return G;
}

/***************************
��ԿPB(PBx,PBy)
***************************/
epoint *CalculatePB()
{

	epoint *PB = (epoint*)malloc(sizeof(epoint));
	PB = epoint_init();
	epoint_set(PBx, PBy, 0, PB);
	return PB;
}

/***************************
��ԿPA(PAx,PAy)
***************************/
epoint *CalculatePA()
{

	epoint *PA = (epoint*)malloc(sizeof(epoint));
	PA = epoint_init();
	epoint_set(PAx, PAy, 0, PA);
	return PA;
}

/**************************************
������Կ��˽Կ
ע�ͣ����ý������ȫ�ֱ���PBX��PBy��DB
**************************************/
void CalculateBKeys()
{
	big dm = mirvar(0);
	dm = GetBigRandom(mirvar(1), Sub2(HexCharsToBig(n), mirvar(1)));	        // ˽Կ	[1,n-1]
	epoint* pm = epoint_init();
	pm = MultiplyEpoint(dm, CalculateG());										// ��Կ 
	PBx = PointX(pm);  //���ù�Կ���������ȫ�ֱ���PBx
	PBy = PointY(pm);  //���ù�Կ���������ȫ�ֱ���PBx
	DB = dm;           //����˽Կ����ȫ�ֱ���DB 
}

/************************************
��֤��Կ��˽Կ
ע�ͣ�ʹ��ȫ�ֱ�����������
************************************/
int VerifyKeys(big x,big y)
{
	if (!compare(Mod2(Pow2(y, 2), HexCharsToBig(p)), Mod2(Add2(Pow2(x, 3), Add2(Multiply2(x, HexCharsToBig(a)), HexCharsToBig(b))), HexCharsToBig(p))))		// if((PBy^2 %p) != ((PBx^3 + a*PBx +b)%p))
	{
		printf("��Կ��֤��Ч������������\n");
		system("pause");
		exit(1);
	}
	printf("��Կ��֤��Ч!\n\n");
	return 1;
}

/*************************************
����(x1,y1)
ע�ͣ�ʹ��ʹ��ȫ�ֱ���k��������
*************************************/
epoint *CalculatePoint1()
{
	return MultiplyEpoint(k, CalculateG());
}

/**********************************
����(x2,y2)
ע�ͣ�ʹ��ȫ�ֱ���k��������
**********************************/
epoint *CalculatePoint2()
{
	return MultiplyEpoint(k, CalculatePB());
}

/************************************
��ȡ�ļ����룬�ַ�����ʾ��������
ע�ͣ��ڲ�����������ȫ�ֱ���
************************************/
void ReadInputFile()
{
	FILE *fp = fopen(inputFileName, "r");
	//�������ļ�
	if (fp == NULL)
	{
		printf("%s������\n", inputFileName);
		system("pause");
		exit(2);
	}
	//��ȡ���ݣ����ܰ����س����ո�ȣ���ʹ��fgetc
	char* data = (char*)malloc(sizeof(char) * Max);  //�ַ���
	int dataSize = 0;
	char ch;
	while ((ch = fgetc(fp)) != EOF)
	{
		data[dataSize] = ch;
		dataSize++;
	}
	fclose(fp);
	data[dataSize] = '\0';

	fileData.data = data;  //���ַ�����ʽ�洢��������
	fileData.size = dataSize;  //�������ַ��ĸ���
}

/*******************************************
����C1 = [k]G����ʮ�����ƴ���ʾ��ռ65�ֽ�
ע�ͣ�ʹ����ȫ�ֱ��������k
*******************************************/
char * CalculateC1()
{
	/*
	*****************point1ʹ����ȫ�ֱ��������k
	*/
	epoint *point1 = CalculatePoint1();

	unsigned char *x1 = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	unsigned char *y1 = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	lengthC1x = big_to_bytes(0, PointX(point1), x1, FALSE) * 2;
	lengthC1y = big_to_bytes(0, PointY(point1), y1, FALSE) * 2;  //�ַ����� * 2 = ʮ�����Ƹ���

	/*
	��Բ���ߵ�-->�ַ���-->ʮ�����ƴ�
	*/
	String *result = EpointToBytes(point1);  //64�ֽڵ�point1ת65�ֽڵ�result  
	char* C1 = ConvertStringAsHex(result);  
	epoint_free(point1);  //�ݴ�������ͷ�
	return C1;
}

/*******************************
����C2�����ַ�����ʾ
ע�ͣ�ʹ����ȫ�ֱ��������k
*******************************/
String * CalculateC2()
{
	String *result = (String*)malloc(sizeof(String));
	epoint *point2 = CalculatePoint2();
	// point2 �� t ��û�б���ʼ��
	big t = KDF(point2, fileData.size);  //KDF����(ʹ��ȫ�ֱ���)

	if (compare(t, mirvar(0)) == 0)  //����
	{
		result->data = NULL;
		result->size = -1;
		return result;
	}

	epoint_free(point2);  //�ݴ�������ͷ�

	/*
	��������M�����������ܳ����������巶Χ������ʹ�ô������㣬��ʹ���ַ������������
	*/
	unsigned char *tString = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	int lengthT = big_to_bytes(0, t, tString, FALSE);		//��tת�����ַ���,�����ַ�����
	if (lengthT != fileData.size)
	{
		for (int i = lengthT - 1; i >= 0; i--)
		{
			tString[fileData.size - lengthT + i] = tString[i];
		}

		for (int i = 0; i < fileData.size - lengthT; i++)
		{
			tString[i] = 0;
		}
		lengthT = fileData.size;  //tString(t)���ַ����Ⱥ�fileData.size(M)�ĳ����Ѿ�һ��
	}

	result->data = (unsigned char*)malloc(sizeof(unsigned char)*lengthT);
	for (int i = 0; i < lengthT; i++)
	{
		result->data[i] = tString[i] ^ fileData.data[i];  //C2 = t ^ M �����ַ�����ʽ��������
	}
	result->size = lengthT;  //��t���ַ����ȸ���C2���ַ�����

	free(tString);
	mirkill(t);

	return result;
}

/***********************
KDF���������ش���
***********************/
big KDF(epoint* point2, int klen)
{
	unsigned char* xStr = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	unsigned char* yStr = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	int lengthX = big_to_bytes(0, PointX(point2), xStr, FALSE);  //�ַ�����
	int lengthY = big_to_bytes(0, PointY(point2), yStr, FALSE);  //�ַ�����
	free(xStr);
	free(yStr);

	big x = PointX(point2);  //����x��ʾpoint2�ĺ�����
	big y = PointY(point2);  //����y��ʾpoint2��������

	big t = mirvar(0);
	big ct = mirvar(1);	 //����������32λ����ֵΪ1
	big V0 = mirvar(0);
	big Ha = mirvar(0);
	big Z = mirvar(0);
	int v = 32;	 //sm3��hashֵ����Ϊ32�ֽ�(256bit)��������λΪ�ֽ�(�ַ�)

	/*
	���Z
	*/
	copy(x, Z);
	sftbit(Z, lengthY * 8, Z);	//����y�ַ�����ռ�ı�������lengthY��ʾ�ַ�����
	add(Z, y, Z);  //Z����ƴ��y ����Z= x||y

	/*
	klen��ʾ�����е��ַ�����
	*/
	if (klen / v >= 1)
	{
		for (int i = 1; i <= klen / v; i++)
		{
			sftbit(Z, 32, t);					//Z����32λ��
			add(t, ct, t);						//t����ƴ��ct

			big sm3Value = SM3(t);  //��t��hashֵ t= Z||ct
			copy(sm3Value, V0);					
			mirkill(sm3Value);
			add(Ha, V0, Ha);					//Ha����ƴ��V0

			sftbit(Ha, 256, Ha);				//Ha����V0λ����Ϊ��һ��ƴ����׼�� Ha= Ha||x||y||ct
			add(ct, mirvar(1), ct);				//��������һ
		}
		sftbit(Ha, -256, Ha);					//ȥ�������һ������
	}

	if (klen%v == 0)	//klen/vΪ����
	{
		//ͬ���㷨
		sftbit(Z, 32, t);						//����32λ
		add(t, ct, t);							//��Ϻ����

		big sm3Value = SM3(t);
		copy(sm3Value, V0);						//��t��hashֵ t= Z||ct
		mirkill(sm3Value);

		sftbit(Ha, 256, Ha);
		add(V0, Ha, Ha);						//��ϣ�������֮ǰ�������
	}
	else
	{
		sftbit(Z, 32, t);						//����32λ
		add(t, ct, t);							//��Ϻ����

		copy(SM3(t), V0);						//��ϣ����������浽V0��,256λ
		sftbit(V0, -(256 - (klen * 8 - (klen / v)*v * 8)), V0);

		sftbit(Ha, klen * 8 - (klen / v)*v * 8, Ha);
		add(Ha, V0, Ha);							//��ϣ�������֮ǰ�������
	}

	mirkill(V0);
	mirkill(x);
	mirkill(y);
	mirkill(t);
	mirkill(ct);
	mirkill(Z);
	return Ha;
}

/********************************
����C3����ʮ�����ƴ���ʾ��ռ32�ֽ�
ע�ͣ�ʹ����ȫ�ֱ��������k
********************************/
char* CalculateC3()
{
	epoint *point2 = CalculatePoint2();

	char* x2 = (char*)malloc(sizeof(char)*Max);
	char* y2 = (char*)malloc(sizeof(char)*Max);
	int lengthX = big_to_bytes(0, PointX(point2), x2, FALSE);  //ʮ�����Ƹ���
	int lengthY = big_to_bytes(0, PointY(point2), y2, FALSE);  //ʮ�����Ƹ���

	epoint_free(point2);//�ݴ�������ͷ�

	/*
	ƴ��ʮ�����ƴ�
	*/
	char* xmy = (char*)malloc(sizeof(char)*(lengthX*2 + lengthY*2 + fileData.size * 2 + 1));  //ʮ�����Ƹ���
	int i = 0;
	for (int j = 0; j < lengthX; j++)
	{
		sprintf(&xmy[i], "%02x", (unsigned char)(x2[j]));  //��16���Ƶĸ�ʽ���unsigned char���͵���ֵ,������Ϊ2,�Ҷ���,��������ַ�0���
		i += 2;
	}

	for (int j = 0; j < fileData.size; j++)
	{
		sprintf(&xmy[i], "%02x", (unsigned char)(fileData.data[j]));
		i += 2;
	}

	for (int j = 0; j < lengthY; j++)
	{
		sprintf(&xmy[i], "%02x", (unsigned char)(y2[j]));
		i += 2;
	}
	xmy[i] = '\0';   //ֱ�Ӹ�ֵ����ֵʱ������\0

	free(x2);
	free(y2);

	xmy = SM3ByHexStr(xmy);  //SM3(x2||data||y2)����ʮ�����ƴ���ʾ
	return xmy;
}



/***********************
*******����ǩ��**********
***********************/
void MakeSign() {

	CalculateAKeys();		//������Կ��˽Կ
	VerifyKeys(PAx, PAy);	//��֤��Կ��˽Կ
	big e = mirvar(0);
	e = CalculateE();

Restart:				//���¿�ʼ���ɲ���
	InitRandomK();	    //��ʼ�������

	big r = mirvar(0);
	r = CalculateR();
	if ((compare(r, mirvar(0)) == 0) || (compare(Add2(r, k), HexCharsToBig(n)) == 0))
	{
		printf("r�������\n");
		goto Restart;
	}

	big s = mirvar(0);
	s = CalculateS();
	if ((compare(s, mirvar(0)) == 0))
	{
		printf("s�������\n");
		goto Restart;
	}

	/*
	ƴ���ַ���
	*/
	char *c = (char*)calloc(strlen(BigToHexChars2(r)) + strlen(BigToHexChars2(s)) + 1, sizeof(char)); //����ʮ�����ƴ������ڴ�
	strcat(c, BigToHexChars2(r));  //strcatƴ��ʱ��c1String�Ḳ��c����\0������c1String����\0
	strcat(c, BigToHexChars2(s));
	signature = c;

	printf("ǩ��:\n%s\n\n", signature);  //ǩ��

}

/*********************
	   ��֤ǩ��
*********************/
void VerifySign() {

	/*
	���ǩ��
	*/
	char* Rstring = GetPartHexStr(signature, 0, lengthRS);
	char* Sstring = GetPartHexStr(signature, strlen(signature) - lengthRS, lengthRS);
	free(signature);
	printf("r=%s\n\n", Rstring);
	printf("s=%s\n\n", Sstring);

	//��֤r
	//��֤s

	/*
	��e
	*/
	big e = mirvar(0);
	e = CalculateE();

	/*
	��t
	*/
	big t = mirvar(0);
	t = Mod2(Add2(HexCharsToBig(Rstring), HexCharsToBig(Sstring)), HexCharsToBig(n));
	if (compare(t, mirvar(0)) == 0)
	{
		printf("tΪ0����֤��ͨ��\n");
		system("pause");
		exit(1);
	}

	/*
	��R���������⣡��������
	*/
	epoint* G = NewPoint(HexCharsToBig(Gx), HexCharsToBig(Gy));
	epoint* PA = CalculatePA();  //PAδ�ı�
	epoint* point = AddEpoint(MultiplyEpoint(HexCharsToBig(Sstring), G), MultiplyEpoint(t, PA));

	big x1 = mirvar(0);
	x1 = PointX(point);
	big R = mirvar(0);
	R = Mod2(Add2(e, x1), HexCharsToBig(n));

	printf("R=%s\n\n", BigToHexChars2(R));

	if (compare(R, HexCharsToBig(Rstring)) == 0)
	{
		printf("��֤ͨ��\n");
	}
	printf("R��r��ƥ�䣬��֤��ͨ��\n");
}

/**************************************
������Կ��˽Կ
ע�ͣ����ý������ȫ�ֱ���PAX��PAy��DA
**************************************/
void CalculateAKeys()
{
	big dm = mirvar(0);
	dm = GetBigRandom(mirvar(1), Sub2(HexCharsToBig(n), mirvar(1)));	        // ˽Կ	[1,n-1]
	epoint* pm = epoint_init();
	pm = MultiplyEpoint(dm, CalculateG());										// ��Կ 
	PAx = PointX(pm);  //���ù�Կ���������ȫ�ֱ���PAx
	PAy = PointY(pm);  //���ù�Կ���������ȫ�ֱ���PAx
	DA = dm;           //����˽Կ����ȫ�ֱ���DA 
}


/*
����E
*/
big CalculateE() {
	/*
	ƴ��ʮ�����ƴ�
	*/
	char *c = (char*)calloc(strlen(ENTL) + strlen(ID) + strlen(a) + strlen(b) + strlen(Gx) + strlen(Gy) + strlen(BigToHexChars2(PBx)) + strlen(BigToHexChars2(PBy)) + 1, sizeof(char));  //����ʮ�����ƴ������ڴ�
	strcat(c, ENTL);
	strcat(c, ID);
	strcat(c, a);
	strcat(c, b);
	strcat(c, Gx);
	strcat(c, Gy);
	strcat(c, BigToHexChars2(PAx));
	strcat(c, BigToHexChars2(PAy));
	char *cM = (char*)calloc(strlen(c) + strlen(ccode) + 1, sizeof(char));  //����ʮ�����ƴ������ڴ�
	strcat(cM, c);  //strcatƴ��ʱ��c1String�Ḳ��c����\0������c1String����\0
	strcat(cM, ccode);
	big E = mirvar(0);
	E = HexCharsToBig(SM3ByHexStr(cM));
	return E;
}

/*
����r
*/

big CalculateR() {
	epoint *point1 = CalculatePoint1();
	big x1 = mirvar(0);
	x1 = PointX(point1);
	big E = mirvar(0);
	E = CalculateE();
	big r = mirvar(0);
	r = Mod2(Add2(E, x1), HexCharsToBig(n));
	return r;
}


/*
����s,*********************************************************8
*/
big CalculateS() {
	big s = mirvar(0);

	big t = mirvar(0);
	t = Mod2(Xor2(Add2(DA, mirvar(1)), mirvar(-1)), HexCharsToBig(n));
	//Sub2(HexCharsToBig(n), mirvar(2))
	big r = mirvar(0);
	r = CalculateR();
	big m = mirvar(0);
	m = Mod2(Sub2(k, Multiply2(r, DA)), HexCharsToBig(n));

	s = Mod2(Multiply2(t, m), HexCharsToBig(n));
	return s;
}




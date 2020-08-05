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
定义给定常量，以十六进制串表示
*/
char* p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
char* a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
char* b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
char* n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
char* Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
char* Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
char* ID = "31323334353637383132333435363738";    //默认ID
char* ENTL = "0080";                              //默认ENTL

/*
*********加密**********
注释：整个加密过程使用同一个随机数k
*/
void Encryption()
{
	CalculateBKeys();		//产生公钥和私钥
	VerifyBKeys();			//验证公钥和私钥
	ReadInputFile();        //读取文件输入

Restart:				//重新开始生成参数
	InitRandomK();			//初始化随机数

	//C1，C3, 十六进制串
	char* c1String = CalculateC1();
	char* c3String = CalculateC3();

	//C2，将字符串形式转换成十六进制串
	String *C2 = CalculateC2();
	if (C2->size <= 0 && C2->data == NULL)	//t全零
	{
		goto Restart;
	}
	char* c2String = ConvertStringAsHex(C2);
	free(C2->data);
	free(C2);

	//打印加密重要参数
	printf("***************椭圆曲线方程为：y^2=x^3+a*x+b\n");
	printf("p=%s\n", p);
	printf("a=%s\n", a);
	printf("b=%s\n", b);
	printf("n=%s\n", n);
	printf("Gx=%s\n", Gx);
	printf("Gy=%s\n", Gy);
	printf("k=%s\n\n", BigToHexChars2(k));
	printf("***************秘钥参数如下****************\n");
	printf("私钥=%s\n\n", BigToHexChars2(DB));
	printf("公钥x=%s\n\n", BigToHexChars2(PBx));
	printf("公钥y=%s\n\n", BigToHexChars2(PBy));
	printf("***************加密中间数据如下************\n");
	printf("C1=%s\n\n", c1String);
	printf("C3=%s\n\n", c3String);
	printf("C2=%s\n\n", c2String);
	

	/*
	拼接字符串
	*/
	char *c = (char*)calloc(strlen(c1String) + strlen(c2String) + strlen(c3String) + 1, sizeof(char));  //完整十六进制串分配内存
	strcat(c, c1String);  //strcat拼接时，c1String会覆盖c串的\0，保留c1String串的\0
	strcat(c, c3String);
	strcat(c, c2String);
	free(c1String); 
	free(c2String);
	free(c3String);
	ccode = c;  

	printf("明文:\n%s\n\n", fileData.data);  //明文数据
	printf("密文：\n%s\n\n\n", ccode);       //密文数据
}


/*
*********解密**********
注释：不涉及随机数k
*/
void Decryption()
{
    
	/*
	椭圆曲线点C1，C2
	*/
	char* x1String = GetPartHexStr(ccode, 2, lengthC1x);  //字符串中4在十六进制串中表示为 “04”
	char* y1String = GetPartHexStr(ccode, 2 + lengthC1x, lengthC1y);
	epoint* C1 = NewPoint(HexCharsToBig(x1String), HexCharsToBig(y1String));
	epoint* C2 = MultiplyEpoint(DB, C1);	//求解 [DB]C1=(x2, y2)
	//printf("point2=%s\n\n", ConvertStringAsHex(EpointToBytes(C2)));
	epoint_free(C1);

	/*
	拆分密文
	*/
	char* C1String = GetPartHexStr(ccode, 0, lengthC1);
	char* C3String = GetPartHexStr(ccode, lengthC1, lengthC3);
	char* C2String = GetPartHexStr(ccode, lengthC1 + lengthC3, strlen(ccode)-lengthC1 - lengthC3);
	//printf("C1=%s\n\n", C1String);
	//printf("C3=%s\n\n", C3String);
	//printf("C2=%s\n\n", C2String);
	free(ccode);

	
	/*
	大数t判零
	*/
	int klen = strlen(C2String) / 2;        //明文数据的字符长度
	big t = KDF(C2, klen);					//求解 t = KDF(x2∥y2,klen)
	if (compare(t, mirvar(0)) == 0)
	{
		printf("解密时t全0，错误\n");
		system("pause");
		exit(3);
	}

	/*
	求得M'
	*/
	big C2Number = mirvar(0);
	C2Number = HexCharsToBig(C2String);
    char* mcode = BigToHexChars2(Xor2(C2Number, t));  
	mirkill(C2Number);

	/*
	拼接十六进制串：xmy = x2  ||  M'  ||  Y2
	*/
	char* xmy = (char*)calloc(strlen(BigToHexChars2(PointX(C2))) + strlen(BigToHexChars2(PointY(C2))) + strlen(mcode) + 1, sizeof(char));
	strcat(xmy, BigToHexChars2(PointX(C2)));
	strcat(xmy, mcode);
	strcat(xmy, BigToHexChars2(PointY(C2)));

	/*
	比较u与C3
	*/
	if (strcmp(SM3ByHexStr(xmy), C3String) != 0)
	{
		printf("破译失败\n");
		return;
	}
	free(xmy);

	printf("经验证，解密成功，明文十六进制串为:\n%s\n", mcode);

	/*
	将大数以字符串形式输出
	*/
	big mNumber = mirvar(0);
	mNumber = HexCharsToBig(mcode);
	char mString[1000];
	int mStringLength = big_to_bytes(0, mNumber, mString, FALSE);  //大数转换成字符串
	mString[mStringLength] = '\0';  //补\0
	printf("翻译成明文为:\n%s\n\n", mString);
}



/*
产生随机数 a<= result <=b
*/
big GetBigRandom(big a, big b)
{
	irand((unsigned)time(NULL));
	big result = mirvar(0);
	bigrand(Add2(Sub2(b, a), mirvar(1)), result);		// 0<= result <b-a+1
	return Add2(result, a);							// a<= xxx <=b
}

/*
产生随机参数K
注释：所得随机数存入全局变量k
*/
void InitRandomK()
{
	k = mirvar(0);
	copy(GetBigRandom(mirvar(1), Sub2(HexCharsToBig(n), mirvar(1))), k);	// 1<= k <= n-1
}

/*
参数G
*/
epoint * CalculateG()
{
	epoint *G = (epoint*)malloc(sizeof(epoint));
	G = epoint_init();
	epoint_set(HexCharsToBig(Gx), HexCharsToBig(Gy), 0, G);
	return G;
}

/*
公钥PB(PBx,PBy)
*/
epoint *CalculatePB()
{

	epoint *PB = (epoint*)malloc(sizeof(epoint));
	PB = epoint_init();
	epoint_set(PBx, PBy, 0, PB);
	return PB;
}

/*
产生公钥和私钥
注释：所得结果存入全局变量PBX，PBy，DB
*/
void CalculateBKeys()
{
	big dm = mirvar(0);
	dm = GetBigRandom(mirvar(1), Sub2(HexCharsToBig(n), mirvar(1)));	        // 私钥	[1,n-1]
	epoint* pm = epoint_init();
	pm = MultiplyEpoint(dm, CalculateG());										// 公钥 
	PBx = PointX(pm);  //所得公钥横坐标存入全局变量PBx
	PBy = PointY(pm);  //所得公钥横坐标存入全局变量PBx
	DB = dm;           //所得私钥存入全局变量DB 
}

/*
验证公钥和私钥
注释：使用全局变量PBx，PBy进行运算
*/
int VerifyBKeys()
{
	if (!compare(Mod2(Pow2(PBy, 2), HexCharsToBig(p)), Mod2(Add2(Pow2(PBx, 3), Add2(Multiply2(PBx, HexCharsToBig(a)), HexCharsToBig(b))), HexCharsToBig(p))))		// if((PBy^2 %p) != ((PBx^3 + a*PBx +b)%p))
	{
		printf("公钥验证无效，请重启程序\n");
		system("pause");
		exit(1);
	}
	printf("公钥验证有效!\n\n");
	return 1;
}

/*
计算(x1,y1)
注释：使用使用全局变量k进行运算
*/
epoint *CalculatePoint1()
{
	return MultiplyEpoint(k, CalculateG());
}

/*
计算(x2,y2)
注释：使用全局变量k进行运算
*/
epoint *CalculatePoint2()
{
	return MultiplyEpoint(k, CalculatePB());
}

/*
读取文件输入，字符串表示明文数据
注释：内部运算结果存入全局变量
*/
void ReadInputFile()
{
	FILE *fp = fopen(inputFileName, "r");
	//打开输入文件
	if (fp == NULL)
	{
		printf("%s不存在\n", inputFileName);
		system("pause");
		exit(2);
	}
	//读取数据，可能包含回车、空格等，故使用fgetc
	char* data = (char*)malloc(sizeof(char) * Max);  //字符串
	int dataSize = 0;
	char ch;
	while ((ch = fgetc(fp)) != EOF)
	{
		data[dataSize] = ch;
		dataSize++;
	}
	fclose(fp);
	data[dataSize] = '\0';

	fileData.data = data;  //以字符串形式存储明文数据
	fileData.size = dataSize;  //明文中字符的个数
}

/*
计算C1 = [k]G，以十六进制串表示，占65字节
注释：使用了全局变量随机数k
*/
char * CalculateC1()
{
	/*
	*****************point1使用了全局变量随机数k
	*/
	epoint *point1 = CalculatePoint1();

	unsigned char *x = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	unsigned char *y = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	lengthC1x = big_to_bytes(0, PointX(point1), x, FALSE) * 2;
	lengthC1y = big_to_bytes(0, PointY(point1), y, FALSE) * 2;  //字符个数 * 2 = 十六进制个数

	/*
	椭圆曲线点-->字符串-->十六进制串
	*/
	String *result = EpointToBytes(point1);  //64字节的point1转65字节的result  
	char* C1 = ConvertStringAsHex(result);  

	epoint_free(point1);  //暂存变量被释放

	return C1;
}

/*
计算C2，以字符串表示
注释：使用了全局变量随机数k
*/
String * CalculateC2()
{
	String *result = (String*)malloc(sizeof(String));
	epoint *point2 = CalculatePoint2();
	// point2 和 t 都没有被初始化
	big t = KDF(point2, fileData.size);  //KDF函数(使用全局变量)

	if (compare(t, mirvar(0)) == 0)  //判零
	{
		result->data = NULL;
		result->size = -1;
		return result;
	}

	epoint_free(point2);  //暂存变量被释放

	/*
	明文数据M不定长，可能超出大数定义范围，不能使用大数运算，故使用字符串求异或运算
	*/
	unsigned char *tString = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	int lengthT = big_to_bytes(0, t, tString, FALSE);		//将t转换成字符串,返回字符个数
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
		lengthT = fileData.size;
	}

	result->data = (unsigned char*)malloc(sizeof(unsigned char)*lengthT);
	for (int i = 0; i < lengthT; i++)
	{
		result->data[i] = tString[i] ^ fileData.data[i];  //C2 = t ^ M ，以字符串形式进行运算
	}
	result->size = lengthT;  //C2的字符个数即t的字符个数

	free(tString);
	mirkill(t);

	return result;
}

/*
KDF函数，返回大数
*/
big KDF(epoint* point2, int klen)
{
	unsigned char* xStr = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	unsigned char* yStr = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	int lengthX = big_to_bytes(0, PointX(point2), xStr, FALSE);  //大数x转换成字符串表示的字符数(字节数)
	int lengthY = big_to_bytes(0, PointY(point2), yStr, FALSE);  //大数y转换成字符串表示的字符数(字节数)
	free(xStr);
	free(yStr);

	big x = PointX(point2);  //大数x表示point2的横坐标
	big y = PointY(point2);  //大数y表示point2的纵坐标

	big t = mirvar(0);
	big ct = mirvar(1);	 //计数器至少32位，初值为1
	big V0 = mirvar(0);
	big Ha = mirvar(0);
	big Z = mirvar(0);
	int v = 32;	 //sm3的hash值长度为32字节(256bit)，基本单位为字节(字符)

	/*
	求解Z
	*/
	copy(x, Z);
	sftbit(Z, lengthY * 8, Z);	//左移y字符串所占的比特数，lengthY表示字符个数
	add(Z, y, Z);  //Z比特拼接y 最终Z= x||y

	/*
	klen表示明文中的字符个数
	*/
	if (klen / v >= 1)
	{
		for (int i = 1; i <= klen / v; i++)
		{
			sftbit(Z, 32, t);					//Z左移32位数
			add(t, ct, t);						//t比特拼接ct

			big sm3Value = SM3(t);  //求t的hash值 t= Z||ct
			copy(sm3Value, V0);					
			mirkill(sm3Value);
			add(Ha, V0, Ha);					//Ha比特拼接V0

			sftbit(Ha, 256, Ha);				//Ha左移V0位数，为下一次拼接做准备 Ha= Ha||x||y||ct
			add(ct, mirvar(1), ct);				//计数器加一
		}
		sftbit(Ha, -256, Ha);					//去掉多出的一次左移
	}

	if (klen%v == 0)	//klen/v为整数
	{
		//同上算法
		sftbit(Z, 32, t);						//左移32位
		add(t, ct, t);							//结合后的数

		big sm3Value = SM3(t);
		copy(sm3Value, V0);						//求t的hash值 t= Z||ct
		mirkill(sm3Value);

		sftbit(Ha, 256, Ha);
		add(V0, Ha, Ha);						//哈希后的数和之前的数相加
	}
	else
	{
		sftbit(Z, 32, t);						//左移32位
		add(t, ct, t);							//结合后的数

		copy(SM3(t), V0);						//哈希后的数，保存到V0中,256位
		sftbit(V0, -(256 - (klen * 8 - (klen / v)*v * 8)), V0);

		sftbit(Ha, klen * 8 - (klen / v)*v * 8, Ha);
		add(Ha, V0, Ha);							//哈希后的数和之前的数相加
	}

	mirkill(V0);
	mirkill(x);
	mirkill(y);
	mirkill(t);
	mirkill(ct);
	mirkill(Z);
	return Ha;
}

/*
计算C3，以十六进制串表示，占32字节
注释：使用了全局变量随机数k
*/
char* CalculateC3()
{
	epoint *point2 = CalculatePoint2();

	char* x = (char*)malloc(sizeof(char)*Max);
	char* y = (char*)malloc(sizeof(char)*Max);
	int lengthX = big_to_bytes(0, PointX(point2), x, FALSE);  //字符个数(字节数)
	int lengthY = big_to_bytes(0, PointY(point2), y, FALSE);  //字符个数(字节数)

	epoint_free(point2);//暂存变量被释放

	/*
	拼接十六进制串
	*/
	char* xmy = (char*)malloc(sizeof(char)*(lengthX * 2 + lengthY * 2 + fileData.size * 2 + 1));  //十六进制个数
	int i = 0;
	for (int j = 0; j < lengthX; j++)
	{
		sprintf(&xmy[i], "%02x", (unsigned char)(x[j]));  //以16进制的格式输出unsigned char类型的数值,输出域宽为2,右对齐,不足的用字符0替代
		i += 2;
	}

	for (int j = 0; j < fileData.size; j++)
	{
		sprintf(&xmy[i], "%02x", (unsigned char)(fileData.data[j]));
		i += 2;
	}

	for (int j = 0; j < lengthY; j++)
	{
		sprintf(&xmy[i], "%02x", (unsigned char)(y[j]));
		i += 2;
	}
	xmy[i] = '\0';   //直接赋值，赋值时不包含\0

	free(x);
	free(y);

	xmy = SM3ByHexStr(xmy);  //hash（x2||data||y2)，以十六进制串表示
	return xmy;
}







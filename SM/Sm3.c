#include<stdlib.h>
#include"miracl.h"
#include"mirdef.h"
#include"Sm3.h"

/*
SM3签名过程
*/
big SM3(big input)
{

	big z = mirvar(1);
	big x = mirvar(1);
	big V = mirvar(0);
	big one = mirvar(1);
	unsigned int V0[8]; 						//V(0)为256比特初始值IV
	big B[5];
	int l;										//消息的长度
	int ll = 63;
	int length[64];								//消息长度的二进制表示 
	int n; 										//迭代次数 
	int i;										//for循环所用 

	for (i = 0; i < 5; i++)
	{
		B[i] = mirvar(0);
	}  //初始化大数数组

	//存储初始值IV
	V0[0] = 0X7380166f;
	V0[1] = 0X4914b2b9;
	V0[2] = 0X172442d7;
	V0[3] = 0Xda8a0600;
	V0[4] = 0Xa96f30bc;
	V0[5] = 0X163138aa;
	V0[6] = 0Xe38dee4d;
	V0[7] = 0Xb0fb0e4e;

	/*
	填充
	*/
	l = 8 * numdig(input);							//返回大数input的比特数
	bTd(length, l);									//将input的长度用二进制表示，放到length数组中 :即用64位二进制数表示input的二进制长度


	//消息input首先填充1
	sftbit(input, 1, z);							//将一个大数左移1位
	incr(z, 1, z);									//加1
	copy(z, input);
	l++;
	//再填充0 
	while (l % 512 != 448)
	{
		sftbit(input, 1, z);						//将一个大数左移n位，直到满足条件
		copy(z, input);
		l++;
	}
	//将length[]填充在input(已填充1000...)后面
	while (ll >= 0)
	{
		sftbit(input, 1, z);						//将一个大数左移1位

		if (length[ll] == 1)
		{
			incr(z, 1, z);							//+1
		}
		copy(z, input);
		ll--;
	}

	
	

	/*
	迭代压缩
	*/
	expb2(512, x);									//2的512次方,结果存入x(B)	
	n = (l + 64) / 512;								//将填充后的input按512bit分组所得分组个数 
	//将输入按照512bit分组，存入大数数组B中
	for (i = 0; i < n; i++)
	{
		powmod(input, one, x, B[n - 1 - i]);		//input(B)的one(B)次方 mod x(B)(值为2的512次方) ，结果存入B[n - 1 - i](B)
		sftbit(input, -512, input);					//右移512位 
	}
	//n轮迭代压缩
	for (i = 0; i < n; i++)
	{
		CF(V0, B[i]);								//传入V(i)，输出V(i+1 ) 
	}
	//取出hash值
	for (i = 0; i < 8; i++)
	{
		*V->w = V0[i];
		V->len = (i + 1) * 8;
		sftbit(V, 32, V);
	}
	sftbit(V, -32, V);  //V(B)右移32位，结果存于V(B)中
	return V;
}

/*
将输入的十六进制串经SM3运算后以十六进制串输出
*/
char* SM3ByHexStr(char* input)
{
	mip->IOBASE = 16;  //置十六进制
	big bigCodeNumber = mirvar(0);  //初始化大数
	cinstr(bigCodeNumber, input);  //将十六进制表示的输入字符串input转换成大数
	big resultNUmber = mirvar(0);  //初始化大数
	copy(SM3(bigCodeNumber), resultNUmber);  //将大数形式的输入字符串经签名后得到的大数形式签名复制给resultNUmber(B)

	char* result = (char*)malloc(sizeof(char)*Max);
	cotstr(resultNUmber, result);  //将签名结果resultNUmber转换成十六进制串

	return result;
}

/*
将输入的十进制整数用二进制表示，存储在数组a中
*/
void  bTd(int *a, int length)
{
	int j = 0;
	int i;
	for (i = 0; i < 64; i++)  //置数组a前64个元素全0
		a[i] = 0;
	while (length > 0)  //除2取余法
	{
		a[j] = length % 2;
		length = length / 2;
		j++;
	}
}

/*
对512bit进行消息扩展和压缩
*/
void CF(unsigned int *V, big B)
{

	int i;
	unsigned int turn;
	unsigned int W[68];
	unsigned int w[64];
	unsigned int a[8];
	unsigned int SS1, SS2, TT1, TT2;
	unsigned int T, G;  //暂存中间数据
	big one;
	big x;
	big input;
	big m;
	big A[8];							//令A,B,C,D,E,F,G,H为字寄存器,
	input = mirvar(1);
	one = mirvar(1);
	x = mirvar(1);
	m = mirvar(1);
	for (i = 0; i < 8; i++)
	{
		a[i] = 0;
	}
	for (i = 0; i < 68; i++)
	{
		W[i] = 0;
	}
	for (i = 0; i < 64; i++)
	{
		w[i] = 0;
	}
	for (i = 0; i < 8; i++)
	{
		A[i] = mirvar(1);
	}
	expb2(32, x);						//2的32次方 
	copy(B, input);

	//将消息分组B(i)划分为16个字W0, W1, · · · , W15
	for (i = 0; i < 16; i++)
	{

		powmod(input, one, x, m);		//求模取余放到m中
		W[15 - i] = *m->w;
		sftbit(input, -32, input);		//右移32位 	
	}
	//b,16-67
	for (i = 16; i < 68; i++)
	{
		turn = P1(W[i - 16] ^ W[i - 9] ^ (Rol(W[i - 3], 15)));
		W[i] = turn ^ (Rol(W[i - 13], 7)) ^ W[i - 6];
	}
	//c,0-63
	for (i = 0; i < 64; i++)
	{
		w[i] = W[i] ^ W[i + 4];
	}
	//ABCDEFGH
	for (i = 0; i < 8; i++)
	{
		a[i] = V[i];  //字数组V中前八个元素是初始值IV
	}
	for (i = 0; i < 64; i++)
	{
		turn = Rol(TT(i), i);
		SS1 = Rol(((Rol(a[0], 12)) + a[4] + turn), 7);
		SS2 = SS1 ^ (Rol(a[0], 12));
		T = FF(i, a[0], a[1], a[2]);
		TT1 = T + a[3] + SS2 + w[i];
		G = GG(i, a[4], a[5], a[6]);
		TT2 = G + a[7] + SS1 + W[i];
		a[3] = a[2];
		a[2] = Rol(a[1], 9);
		a[1] = a[0];
		a[0] = TT1;
		a[7] = a[6];
		a[6] = Rol(a[5], 19);
		a[5] = a[4];
		a[4] = P0(TT2);
	}
	for (i = 0; i < 8; i++)
	{
		V[i] = V[i] ^ a[i];  //a[i]在上述的64轮变换中值已经改变
	}
}

//移位运算
unsigned int Rol(unsigned int n, int m)
{
	n = ((n) << m) | (n >> (32 - m));
	return n;

}


//置换函数P0
unsigned int P0(unsigned int TT2)
{
	return TT2 ^ (Rol(TT2, 9)) ^ (Rol(TT2, 17));
}


//置换函数P1
unsigned int P1(unsigned m)
{
	m = m ^ (Rol(m, 15)) ^ (Rol(m, 23));
	return m;
}

//常量T
unsigned int TT(int j)
{
	unsigned int a = 0X79cc4519;
	unsigned int b = 0X7a879d8a;
	if (j >= 0 && j <= 15)
	{
		return a;
	}
	else
	{
		return b;
	}
}

//布尔函数FF
unsigned int FF(int i, unsigned int a, unsigned int b, unsigned int c)
{
	if (i >= 0 && i <= 15)
	{
		return a ^ b^c;
	}
	else
	{
		return (a&b) | (a&c) | (b&c);
	}
}
//布尔函数GG
unsigned int GG(int i, unsigned int a, unsigned int b, unsigned int c)
{
	if (i >= 0 && i <= 15)
	{
		return a ^ b^c;
	}
	else
	{
		return (a&b) | (~a&c);
	}
}

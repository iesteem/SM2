#include"String.h"
#include"Operation.h"
#include<stdlib.h>
#include"miracl.h"
#include"mirdef.h"

/*
创建一个epoint
*/
epoint* NewPoint(big x, big y)
{
	epoint* result = (epoint*)malloc(sizeof(epoint));
	result = epoint_init();
	epoint_set(x, y, 0, result);
	return result;
}

/*
a(E) + b(E)
*/
epoint* AddEpoint(epoint* a, epoint* b)
{
	epoint* result = (epoint*)malloc(sizeof(epoint));
	result = epoint_init();
	epoint_copy(b, result);
	ecurve_add(a, result);
	return result;
}

/*
a(B) * b(E)
*/
epoint* MultiplyEpoint(big a, epoint* b)
{
	epoint* result = (epoint*)malloc(sizeof(epoint));
	result = epoint_init();
	ecurve_mult(a, b, result);
	return result;
}

/*
从epoint中获取x(B)
*/
big PointX(epoint* point)
{
	big x = mirvar(0);  //每个big类型被创建后必须赋初值
	big y = mirvar(0);
	epoint_get(point, x, y);
	mirkill(y);  //释放此大数占用的内存
	return x;
}

/*
从epoint中获取y(B)
*/
big PointY(epoint* point)
{
	big x = mirvar(0);
	big y = mirvar(0);
	epoint_get(point, x, y);
	mirkill(x);
	return y;
}


/*
将Epoint转化成字符串,首字节为04h
*/
String* EpointToBytes(epoint *point)
{
	unsigned char *x = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	unsigned char *y = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	int lengthX = big_to_bytes(0, PointX(point), x, FALSE);  //字符串长度
	int lengthY = big_to_bytes(0, PointY(point), y, FALSE);  //字符串长度

	String *result = (String*)malloc(sizeof(String));
	result->size = lengthX + lengthY + 1;  //String长度
	result->data = (unsigned char*)malloc(sizeof(unsigned char)*(result->size));

	int i = 0;
	result->data[i++] = 4;  //result字符数组以 4 开头

	for (int j = 0; j < lengthX; j++)
	{
		result->data[i++] = x[j];
	}  //接着存入x

	for (int j = 0; j < lengthY; j++)
	{
		result->data[i++] = y[j];
	}  //再存入y

	return result;		// 4 || point->X || point->Y(字符串)
}


/*
x(B) 异或 y(B)
*/
big Xor2(big x, big y)
{
	big result = mirvar(0);
	unsigned char xString[1000];
	unsigned char yString[1000];
	int lengthX = big_to_bytes(0, x, xString, FALSE);  //将x(B)转换成字符串xString，从索引0开始，返回字符串的长度
	int lengthY = big_to_bytes(0, y, yString, FALSE);

	if (lengthX < lengthY)
	{
		for (int i = 0; i < lengthX; i++)
		{
			yString[lengthY - 1 - i] ^= xString[lengthX - 1 - i];  //从最低位开始异或运算
		}
		bytes_to_big(lengthY, yString, result);  //将字符串yString的前lengthY个字符 转换成大数result
	}
	else
	{
		for (int i = 0; i < lengthY; i++)
		{
			xString[lengthX - 1 - i] ^= yString[lengthY - 1 - i];
		}
		bytes_to_big(lengthX, xString, result);
	}

	return result;
}

/*
x(B) + y(B)
*/
big Add2(big x, big y)
{
	big result = mirvar(0);
	add(x, y, result); //令x(B) + y(B)，结果赋给result(B)
	return result;
}

/*
x(B) - y(B)
*/
big Sub2(big x, big y)
{
	big result = mirvar(0);
	subtract(x, y, result);  //令x(B) - y(B)，结果赋给result(B)
	return result;
}

/*
x(B) * y(B)
*/
big Multiply2(big x, big y)
{
	big result = mirvar(0);
	multiply(x, y, result);  //令x(B) * y(B)，结果赋给result(B)
	return result;
}

/*
x(B) / y(B)
*/
big Divide2(big x, big y)
{
	big x1 = mirvar(0);
	big y1 = mirvar(0);
	big z1 = mirvar(0);
	copy(x, x1);
	copy(y, y1);
	divide(x1, y1, z1);  //令x(B) / y(B)，结果赋给result(B)
	mirkill(x1);
	mirkill(y1);
	return z1;
}

/*
x(B) % y(B)
*/
big Mod2(big x, big y)
{
	big x1 = mirvar(0);
	big y1 = mirvar(0);
	big z1 = mirvar(0);
	copy(x, x1);
	copy(y, y1);
	powmod(x1, mirvar(1), y1, z1);  //令 x1(B)的1(B)次方 mod y1(B), 结果赋给result(B)
	mirkill(x1);
	mirkill(y1);
	return z1;
}

/*
x(B)的y次方
*/
big Pow2(big x, int y)
{
	big x1 = mirvar(0);
	big y1 = mirvar(0);
	copy(x, x1);  //将x1(B)赋给x(B)
	for (int i = 0; i < y; i++)
	{
		y1 = Multiply2(x1, x1);
	}
	mirkill(x1);
	return y1;
}


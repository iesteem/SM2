#include"String.h"
#include"Operation.h"
#include<stdlib.h>
#include"miracl.h"
#include"mirdef.h"

/*
����һ��epoint
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
��epoint�л�ȡx(B)
*/
big PointX(epoint* point)
{
	big x = mirvar(0);  //ÿ��big���ͱ���������븳��ֵ
	big y = mirvar(0);
	epoint_get(point, x, y);
	mirkill(y);  //�ͷŴ˴���ռ�õ��ڴ�
	return x;
}

/*
��epoint�л�ȡy(B)
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
��Epointת�����ַ���,���ֽ�Ϊ04h
*/
String* EpointToBytes(epoint *point)
{
	unsigned char *x = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	unsigned char *y = (unsigned char*)malloc(sizeof(unsigned char)*Max);
	int lengthX = big_to_bytes(0, PointX(point), x, FALSE);  //�ַ�������
	int lengthY = big_to_bytes(0, PointY(point), y, FALSE);  //�ַ�������

	String *result = (String*)malloc(sizeof(String));
	result->size = lengthX + lengthY + 1;  //String����
	result->data = (unsigned char*)malloc(sizeof(unsigned char)*(result->size));

	int i = 0;
	result->data[i++] = 4;  //result�ַ������� 4 ��ͷ

	for (int j = 0; j < lengthX; j++)
	{
		result->data[i++] = x[j];
	}  //���Ŵ���x

	for (int j = 0; j < lengthY; j++)
	{
		result->data[i++] = y[j];
	}  //�ٴ���y

	return result;		// 4 || point->X || point->Y(�ַ���)
}


/*
x(B) ��� y(B)
*/
big Xor2(big x, big y)
{
	big result = mirvar(0);
	unsigned char xString[1000];
	unsigned char yString[1000];
	int lengthX = big_to_bytes(0, x, xString, FALSE);  //��x(B)ת�����ַ���xString��������0��ʼ�������ַ����ĳ���
	int lengthY = big_to_bytes(0, y, yString, FALSE);

	if (lengthX < lengthY)
	{
		for (int i = 0; i < lengthX; i++)
		{
			yString[lengthY - 1 - i] ^= xString[lengthX - 1 - i];  //�����λ��ʼ�������
		}
		bytes_to_big(lengthY, yString, result);  //���ַ���yString��ǰlengthY���ַ� ת���ɴ���result
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
	add(x, y, result); //��x(B) + y(B)���������result(B)
	return result;
}

/*
x(B) - y(B)
*/
big Sub2(big x, big y)
{
	big result = mirvar(0);
	subtract(x, y, result);  //��x(B) - y(B)���������result(B)
	return result;
}

/*
x(B) * y(B)
*/
big Multiply2(big x, big y)
{
	big result = mirvar(0);
	multiply(x, y, result);  //��x(B) * y(B)���������result(B)
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
	divide(x1, y1, z1);  //��x(B) / y(B)���������result(B)
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
	powmod(x1, mirvar(1), y1, z1);  //�� x1(B)��1(B)�η� mod y1(B), �������result(B)
	mirkill(x1);
	mirkill(y1);
	return z1;
}

/*
x(B)��y�η�
*/
big Pow2(big x, int y)
{
	big x1 = mirvar(0);
	big y1 = mirvar(0);
	copy(x, x1);  //��x1(B)����x(B)
	for (int i = 0; i < y; i++)
	{
		y1 = Multiply2(x1, x1);
	}
	mirkill(x1);
	return y1;
}


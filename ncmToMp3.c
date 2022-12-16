/*
* date:2022-12-12
* author: FL
* purpose: ncm file to mp3
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "cJSON.h"

#ifdef WIN32
#include<Windows.h>
//����ת���õ��ַ���ָ��
unsigned char* utf8ToGbk(unsigned char*src,int len)
{
	wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len+2);
	unsigned char* newSrc = (unsigned char*)malloc(sizeof(unsigned char) * len + 2);
	
	MultiByteToWideChar(CP_UTF8, 0, src, -1, tmp, len);	//תΪunicode
	WideCharToMultiByte(CP_ACP, 0, tmp, -1, newSrc, len+2, NULL,NULL); //תgbk
	
	return newSrc;
}
#endif



void swap(unsigned char* a, unsigned char* b)
{
	unsigned char t = *a;
	*a = *b;
	*b = t;
}

//��key����S��
/*
* s: s��
* key: ��Կ
* len: ��Կ����
*/
void rc4Init(unsigned char* s, const unsigned char* key, int len)
{
	int i = 0, j = 0;
	unsigned char T[256] = { 0 };

	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		T[i] = key[i % len];
	}

	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + T[i]) % 256;
		swap(s + i, s + j);
	}
}
//���NCM�ļ��Ľ���
//����ϵ
/*
* s: s��
* data: Ҫ���ܻ��߽��ܵ�����
* len: data�ĳ���
*/
void rc4PRGA(unsigned char* s, unsigned char* data, int len)
{
	int i = 0;
	int j = 0;
	int k = 0;
	int idx = 0;
	for (idx = 0; idx < len; idx++)
	{
		i = (idx + 1) % 256;
		j = (i + s[i]) % 256;
		k = (s[i] + s[j]) % 256;
		data[idx] ^= s[k];  //���
	}
}

//base64 ����
/*
* code: Ҫ���������
*/
unsigned char* base64_decode(unsigned char* code, int len, int* actLen)
{
	//����base64�����ַ��ҵ���Ӧ��ʮ��������  
	int table[] = { 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,0,0,0,0,0,
			 0,0,0,0,0,0,0,62,0,0,0,
			 63,52,53,54,55,56,57,58,
			 59,60,61,0,0,0,0,0,0,0,0,
			 1,2,3,4,5,6,7,8,9,10,11,12,
			 13,14,15,16,17,18,19,20,21,
			 22,23,24,25,0,0,0,0,0,0,26,
			 27,28,29,30,31,32,33,34,35,
			 36,37,38,39,40,41,42,43,44,
			 45,46,47,48,49,50,51
	};
	long str_len;
	unsigned char* res;
	int i, j;

	//����������ַ�������  
	//�жϱ������ַ������Ƿ���=
	if (strstr(code, "=="))
		str_len = len / 4 * 3 - 2;
	else if (strstr(code, "="))
		str_len = len / 4 * 3 - 1;
	else
		str_len = len / 4 * 3;

	*actLen = str_len;
	res = malloc(sizeof(unsigned char) * str_len + 1);
	res[str_len] = '\0';

	//��4���ַ�Ϊһλ���н���  
	for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
	{
		res[j] = ((unsigned char)table[code[i]]) << 2 | (((unsigned char)table[code[i + 1]]) >> 4); 
		res[j + 1] = (((unsigned char)table[code[i + 1]]) << 4) | (((unsigned char)table[code[i + 2]]) >> 2);  
		res[j + 2] = (((unsigned char)table[code[i + 2]]) << 6) | ((unsigned char)table[code[i + 3]]); 
	}
	return res;

}
void readFileData(const char* fileName)
{
	FILE* f;
	f = fopen(fileName, "rb");
	if (!f)
	{
		printf("No such file: %s\n", fileName);
		return;
	}
	
	unsigned char buf[16];
	int len=0;
	int i = 0;

	unsigned char meta_key[] = { 0x23,0x31,0x34,0x6C,0x6A,0x6B,0x5F,0x21,0x5C,0x5D,0x26,0x30,0x55,0x3C,0x27,0x28 };
	unsigned char core_key[] = { 0x68,0x7A,0x48,0x52,0x41,0x6D,0x73,0x6F,0x35,0x6B,0x49,0x6E,0x62,0x61,0x78,0x57 };
	
	fseek(f, 10, SEEK_CUR); //f�ӵ�ǰλ���ƶ�10���ֽ�
	fread(buf, 1, 4, f);    //��ȡrc4 key �ĳ���

	len = (buf[3] << 8 | buf[2]) << 16 | (buf[1] << 8 | buf[0]);
	unsigned char* rc4Key= (unsigned char*)malloc(sizeof(unsigned char) * len);
	fread(rc4Key, 1, len, f);   //��ȡrc4����

	//����rc4��Կ
	for (i = 0; i < len; i++)
	{
		rc4Key[i] ^= 0x64;
	}
	
	struct AES_ctx ctx;	
	AES_init_ctx(&ctx, core_key);	//ʹ��core_key��Կ
	int packSize = len / 16;	//���õ���AES-ECB���ܷ�ʽ����Pkcs7padding���
	for (i = 0; i < packSize; i++)
	{
		AES_ECB_decrypt(&ctx, &rc4Key[i * 16]);
	}
	int pad = rc4Key[len - 1];	//��ȡ���ĳ���
	rc4Key[len - pad] = '\0';	//ȥ�����Ĳ��֣��õ�RC4��Կ


	fread(buf, 1, 4, f);    //��ȡMusic Info ��������
	len = ((buf[3] << 8 | buf[2]) << 16) | (buf[1] << 8 | buf[0]);
	unsigned char* meta = (unsigned char*)malloc(sizeof(unsigned char) * len);
	fread(meta, 1, len, f); //��ȡMusic Info����
	//����Music info��Ϣ
	for (i = 0; i < len; i++)
	{
		meta[i] ^= 0x63;
	}
	int act = 0;
	unsigned char* data = base64_decode(&meta[22], len - 22, &act);	//base64����
	AES_init_ctx(&ctx, meta_key);	//AES����
	packSize = act / 16;
	for (i = 0; i < packSize; i++)
	{
		AES_ECB_decrypt(&ctx, &data[i * 16]);
	}
	pad = data[act - 1];
	data[act - pad] = '\0';	//ȥ����䲿��
	unsigned char* newData = data;
#ifdef WIN32
	
	newData = utf8ToGbk(data, strlen(data));
	
#endif
	
	cJSON* cjson = cJSON_Parse(&newData[6]);	//json��������ȡ��ʽ�����ֵ�
	if (cjson == NULL)
	{
		printf("cjson parse failed\n");
		return;
	}
	printf("%s\n", cJSON_Print(cjson));	//���json



	fseek(f, 9, SEEK_CUR);  //�ӵ�ǰλ������9���ֽ�
	fread(buf, 1, 4, f);    //��ȡͼƬ��С
	len = (buf[3] << 8 | buf[2]) << 16 | (buf[1] << 8 | buf[0]);
	unsigned char* img = (unsigned char*)malloc(sizeof(unsigned char) * len);
	fread(img, 1, len, f);  //��ȡͼƬ����



	int offset= 1024 * 1024 * 10;    //10MB ��������һ��Ƚϴ�һ�ζ���10MB
	int total = 0;
	int reSize = offset;
	unsigned char* musicData = (unsigned char*)malloc(offset); //10m
	
	while (!feof(f))
	{
		len = fread(musicData+total, 1, offset, f);	//ÿ�ζ�ȡ10M
		total += len;
		reSize += offset;
	    musicData=realloc(musicData,reSize);	//����
	}
	
	unsigned char sBox[256] = { 0 };	//s��
	rc4Init(sBox, &rc4Key[17], strlen(&rc4Key[17]));	//��rC4��Կ���г�ʼ��s��
	rc4PRGA(sBox, musicData, total);	//����

	//ƴ���ļ���(artist + music name+format)
	char* musicName = cJSON_GetObjectItem(cjson, "musicName")->valuestring;
	cJSON* sub = cJSON_GetObjectItem(cjson, "artist");
	char*artist=cJSON_GetArrayItem(cJSON_GetArrayItem(sub, 0),0)->valuestring;
	char* format = cJSON_GetObjectItem(cjson, "format")->valuestring;
	char* saveFileName =(char*)malloc(strlen(musicName) + strlen(artist) + strlen(format)+5);
	sprintf(saveFileName, "%s - %s.%s", artist, musicName, format);
	FILE* fo=fopen(saveFileName, "wb");
	if (fo == NULL)
	{
		printf("The fileName - '%s' is invalid in this system\n", saveFileName);
	}
	else
	{
		fwrite(musicData, 1, total, fo);
		fclose(fo);
	}
	
	
#ifdef WIN32
	free(newData);
#endif
	free(data);
	free(meta);
	free(img);
	free(musicData);
	fclose(f);
	
}

int main(int argc,char**argv)
{	
	//test

	readFileData("�Y���Х�� - �����`�ȹ¶����n������.ncm");
	/*if (argc > 1)
	{	
		printf("%s\n", argv[0]);
		readFileData(argv[1]);
	}
	else
	{
		printf("No input file\n");
	}*/
	return 0;
}
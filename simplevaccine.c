// simplevaccine.c
/****************************************************************************
���� ��Ī : simplevaccine.c
�� �� : ��ũ�� �����ϴ� ���� ��� �Ǽ��ڵ� Ž���� ���� Simple Vaccine Anti-virus ���α׷� ����
�Լ� ��Ī : main, OpenDirectory, PrintErrMsg, check, check_result
��     �� : Ž���� ���� �� ���� ����, �ɸ� �ð�, �Ǽ��ڵ� ���� ���� �� ���
��     �� : ������α׷���� ���丮�� �Բ� ���� ex) Vaccine C:\temp
�� �� �� : �Ǽ���
�ۼ� ���� : 2016/10/17
*****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <errno.h>
#include <string.h>

#pragma warning(disable:4996)

#ifndef MAX_PATH
#define MAX_PATH	4096
#endif

#define TRUE 1
#define FALSE 0

extern int errno;

typedef int BOOL;

void OpenDirectory(const char* drive);
int check(const char* filename);
void PrintErrMsg();
//void check_result(const char* name);


int main(int argc, char** argv)
{
	char* drivedisp = NULL;
	drivedisp = argv[1]; //2��° ���� drivedisp ������ ������ ����.

	if (argc>1)
	{
		OpenDirectory(drivedisp); //���丮 �˻� �Լ� ȣ��.
	}
	else //2��° ���ڰ� �Էµ��� ���� ��� ���α׷� ���� ���.
	{
		printf("���α׷� �̸� : %s\n", argv[0]);
		puts("Copyright 2015 TUgrape Corporation.\n");
		puts("ver 1.1\n");
		puts("Maker: tu.Grape team (Sungjun Gwon)");
	}
	return 0;
}

void OpenDirectory(const char* drive) // ���丮, ���� �˻� & check �˻� �Լ� ȣ��.
{
	struct _finddata_t fd;
	int next = 1;
	int len;
	char nextpath[MAX_PATH] = { NULL };

	strcpy(nextpath, drive);
	strcat(nextpath, "\\*.*"); // ��η� ���� ���ڿ��� ���ϵ� ī�幮�ڸ� ����.

	long value = _findfirst(nextpath, &fd); // �ش� ��ο��� �켱 ù��° ������ �˻� �ϱ� ���� �Լ�.

	if (value == -1) { //������ �˻� �� �� ���ٸ� �����޼��� ��� �� ����.
		PrintErrMsg();
		return;
	}

	while (next != -1)
	{
		if ((fd.attrib & _A_SUBDIR))  //���� ���丮 ���� �ľ� (ã�� ������ ���丮���� �ľ��Ѵ�)
		{
			if (fd.name[0] != '.' && fd.name[0] != '..') // ., .. ���丮 ���� (��Ʈ���丮 ����)
			{
				len = strlen(nextpath);
				strcpy(&nextpath[len - 3], fd.name);

				OpenDirectory(nextpath); //���ȣ��
			}
		}

		else // ������ ���丮 ������ ��� File ��� & �˻��Լ� ȣ��
		{
			strcpy(nextpath, drive);
			len = strlen(nextpath);
			strcpy(&nextpath[len - 3], fd.name);
			printf("%s\n", nextpath);
			check((const char*)nextpath); //�˻��Լ� ȣ��
			printf("\n");
		}
		next = _findnext(value, &fd);
	}
	_findclose(value);
}

int check(const char* filename) {  //�˻��Լ� (���� ��)

	FILE *in;
	FILE *on;
	char *buffer_f1;
	char *buffer_f2;
	char *buffer_f3;
	long n_size1;
	int j;
	size_t result;
	size_t result_t;
	int pa = 0;

	if ((in = fopen(filename, "rb")) == NULL) //�˻� ��� ���� OPEN
	{
		printf("vacant file");
		return 0;
	}

	//���� ũ�� ����
	fseek(in, 0, SEEK_END);
	n_size1 = ftell(in);
	rewind(in);

	buffer_f1 = (char*)malloc(sizeof(char)*n_size1); // ��ü ������ ������ ���� �� ���� ������ ũ��� �޸𸮸� �Ҵ��Ѵ�. 
	buffer_f2 = (char*)malloc(sizeof(char)*n_size1);
	buffer_f3 = (char*)malloc(sizeof(char)*n_size1);

	fread(buffer_f1, 1, n_size1, in);

	if ((on = fopen("c:\\pattern.txt", "rb")) == NULL) { //�������� OPEN
		puts("pattern error");
		return 0;
	}

	while (fgets(buffer_f2, 16, on) != NULL) {

		itoa((int)buffer_f1, buffer_f3, 16); //�˻������� 16����ȭ�ϰ� buffer_f3�� ����

		if (strstr(buffer_f3, buffer_f2) != NULL) //���ڿ���(�˻�������,����)
		{
			printf(" �ءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءڡڡڡڡ�Malware�ڡڡڡڡڡءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءءء� \n");
			printf("============================================�Ǽ��ڵ� ����:%s============================================\n", filename);
		}

	}

	free(buffer_f1);
	free(buffer_f3);
	free(buffer_f2);
	fclose(in);
	fclose(on);
}

void PrintErrMsg() //�����޼���
{
	switch (errno)
	{
	case EINVAL:
		printf("Invalid parameter: filespec or fileinfo was NULL. Or, the operating system returned an unexpected error.\n");
		break;

	case ENOENT:
		printf("File specification that could not be matched.\n");
		break;

	case ENOMEM:
		printf("Not enough memory or the file name given was greater than MAX_PATH.\n");
		break;

	default:
		printf("Unknown Error\n");
	}
}
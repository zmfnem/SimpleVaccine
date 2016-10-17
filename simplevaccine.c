// simplevaccine.c
/****************************************************************************
파일 명칭 : simplevaccine.c
기 능 : 디스크에 존재하는 파일 기반 악성코드 탐지를 위한 Simple Vaccine Anti-virus 프로그램 제작
함수 명칭 : main, OpenDirectory, PrintErrMsg, check, check_result
출     력 : 탐지한 파일 및 폴더 개수, 걸린 시간, 악성코드 파일 개수 등 출력
입     력 : 백신프로그램명과 디렉토리명 함께 실행 ex) Vaccine C:\temp
작 성 자 : 권성준
작성 일자 : 2016/10/17
*****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <errno.h>
#include <string.h>


extern int errno;

#ifndef MAX_PATH
#define MAX_PATH	4096
#endif

#define TRUE 1
#define FALSE 0

typedef int BOOL;

void OpenDirectory(const char* drive);
void PrintErrMsg();
int check(const char* filename);
void check_result(const char* name);


int main(int argc, char** argv)

{
	char* drivedisp = NULL;
	drivedisp = argv[1]; //2번째 인자 drivedisp 포인터 변수에 저장

	if (argc>1)
	{
		OpenDirectory(drivedisp); //디렉토리 검사 함수 호출
	}

	else
	{
		printf("프로그램 이름 : %s\n", argv[0]);
		puts("Copyright 2015 TUgrape Corporation.\n");
		puts("ver 1.1\n");
		puts("Maker: tu.Grape team (Sungjun Gwon)");
	}

	return 0;
}

void OpenDirectory(const char* drive) // 디렉토리, 파일 검색
{
	struct _finddata_t fd;
	int next = 1;
	FILE *in;
	int len;
	char nextpath[MAX_PATH];

	long value = _findfirst(drive, &fd); //파일이 디스크에 존재하는지 파악하기 위한 함수

	if (value == -1) {
		PrintErrMsg();
		return;
	}


	while (next != -1)
	{
		if ((fd.attrib & _A_SUBDIR) && fd.name[0] != '.') //서브 디렉토리인지 아닌지 파악 and 루트디렉토리 제외
		{
			strcpy(nextpath, drive);

			len = strlen(nextpath);
			strcpy(&nextpath[len - 3], fd.name);

			strcat(nextpath, "\\*.*");
			printf("%s\n", nextpath);

			OpenDirectory(nextpath); //재귀호출
		}

		else //File 검사
		{
			strcpy(nextpath, drive);

			len = strlen(nextpath);
			strcpy(&nextpath[len - 3], fd.name);

			printf("%s\n", nextpath);
			check((const char*)nextpath); //검사함수 호출
			printf("\n");

		}
		next = _findnext(value, &fd);
	}

	_findclose(value);
}


void PrintErrMsg() //에러메세지
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


int check(const char* filename) {  //검사

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

	if ((in = fopen(filename, "rb")) == NULL) //검사 대상 파일 OPEN
	{
		printf("vacant file");
		return 0;
	}

	//파일 크기 추출
	fseek(in, 0, SEEK_END);
	n_size1 = ftell(in);
	rewind(in);

	buffer_f1 = (char*)malloc(sizeof(char)*n_size1); // 전체 파일의 내용을 받을 수 있을 정도의 크기로 메모리를 할당한다. 
	buffer_f2 = (char*)malloc(sizeof(char)*n_size1);
	buffer_f3 = (char*)malloc(sizeof(char)*n_size1);

	fread(buffer_f1, 1, n_size1, in);

	if ((on = fopen("c:\\pattern.txt", "rb")) == NULL) { //패턴파일 OPEN
		puts("pattern error");
		return 0;
	}

	while (fgets(buffer_f2, 16, on) != NULL) {

		itoa((int)buffer_f1, buffer_f3, 16); //검사대상파일 16진수화하고 buffer_f3에 저장

		if (strstr(buffer_f3, buffer_f2) != NULL) //문자열비교(검사대상파일,패턴)
		{
			printf(" ※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※★★★★★Malware★★★★★※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※※ \n");
			printf("============================================악성코드 검출:%s============================================\n", filename);
		}

	}

	free(buffer_f1);
	free(buffer_f3);
	free(buffer_f2);
	fclose(in);
	fclose(on);
}
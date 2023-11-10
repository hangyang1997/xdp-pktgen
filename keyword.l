KW_BEGIN
%{
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <readline/readline.h>
#include <sys/types.h>
#include <readline/history.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include "xlog.h"
#include "xtask.h"
#include "command.h"
#include "xconfig.h"
#include "keyword.h"
#include "xutil.h"

#define YY_READ_BUF_SIZE 8192
#define YY_INPUT(buf, result, max_size) result = xcmd_input(buf, max_size)

static int stdin_dup;
const char *current_line;

// key_word_load_check
KW_LOAD_CHECK("set", "quit", "enter");

void L_ins_save(const char *filename)
{
	FILE *fp;
	HIST_ENTRY **entrys;

	fp = fopen(filename, "w");
	if (fp == NULL) {
		LOG("file %s open failed %s", filename, strerror(errno));
		return;
	}

	entrys = history_list();
	if (!entrys) {
		goto end;
	}

	for (int i = 0; entrys[i]; ++i) {
		if (key_word_load_check(entrys[i]->line))
			fprintf(fp, "%s\n", entrys[i]->line);
	}
end:
	fclose(fp);
}

void L_ins_load(const char *filename)
{
	int fd;

	stdin_dup = dup(0);
	close(0);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		LOG("open file %s error %s",filename, strerror(errno));
		dup(stdin_dup);
		close(stdin_dup);
		return;
	}
}

static size_t xcmd_input(char *buffer, size_t max)
{
	char prompt[0xff];
	char *line;
	size_t len;

	if (current_line) {
		return 0;
	}

	if (current_task) {
		snprintf(prompt, sizeof(prompt), "\033[33;3mXPKT(%s-%d)>\033[0m ", current_task->ifname, current_task->queue_id);
		line = readline(prompt);
	} else {
		line  = readline("\033[3mXPKT>\033[0m ");
	}
	if (!line || line[0] == 0) {
		if (stdin_dup > 0) {
			close(0);
			dup(stdin_dup);
			close(stdin_dup);
			stdin_dup = 0;
			printf("\r");
		}
		return 0;
	}

	len = strlen(line) + 1;
	len = len > max ? max : len;
	strcpy(buffer, line);
	current_line = line;

	return len;
}

#define make_token() (yytext)

static inline int parse_ip_range (uint32_t *begin, uint32_t *end, char *ip_string)
{
	char *tok;

	tok = strstr(ip_string, "-");
	if (tok) {
		*tok = '\0';
		tok++;
	} else {
		tok = ip_string;
	}
	*begin = inet_addr(ip_string);
	*end = inet_addr(tok);

	if (*begin == 0 || *end == 0) {
		return -1;
	}

	return 0;
}

static inline int parse_mac(__u8 *mac, const char *string)
{
	return 6 != sscanf (string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}


%}

%option noyywrap
%option noinput
%option nounput

IP [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+
MAC [0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+

%x STRING

%%

<INITIAL>"set" 		return SET;
<INITIAL>"list"		return LIST;
<INITIAL>"start"	return START;
<INITIAL>"stop"		return STOP;
<INITIAL>"enter"	return ENTER;
<INITIAL>"quit"		return QUIT;
<INITIAL>"save"		return SAVE;
<INITIAL>"load"		return LOAD;

<INITIAL>"dmac"			return DMAC;
<INITIAL>"smac"			return SMAC;
<INITIAL>"daddr"		return DADDR;
<INITIAL>"saddr"		return SADDR;
<INITIAL>"dport"		return DPORT;
<INITIAL>"sport"		return SPORT;
<INITIAL>"packet"		return PACKET;
<INITIAL>"interface"	return INTERFACE;
<INITIAL>"time"			return TIME;
<INITIAL>"queue"		return QUEUE;
<INITIAL>"core"			return CORE;
<INITIAL>"clean"		return CLEAN;
<INITIAL>"all"			return ALL;

<INITIAL>"true"		{ yylval.boolean = 1; return BOOL; }
<INITIAL>"false"	{ yylval.boolean = 0; return BOOL; }
<INITIAL>"tcp-syn"	{ yylval.ptt = PTT_TCP_SYN; return PTTV; }
<INITIAL>"udp"		{ yylval.ptt = PTT_UDP; return PTTV; }


<INITIAL>[0-9]+ {
	yylval.number = atoi(make_token());
	return NUMBER;
}

<INITIAL>{IP} {
	if (!parse_ip_range(&yylval.number, &yylval.number, make_token())) {
		return IP;
	} else {
		LOG("err ip [%s] - ignore", make_token());
	}
}

<INITIAL>{IP}-{IP} {
	if (!parse_ip_range(&yylval.ipr.begin, &yylval.ipr.end, make_token())) {
		return IP_RANGE;
	} else {
		LOG("err ip range [%s] - ignore", make_token());
	}
}

<INITIAL>[0-9]{1,5}-[0-9]{1,5}+ {
	char *num_str = make_token();
	char *endptr;
	yylval.ru16.begin = strtoul(num_str, &endptr, 10);
	yylval.ru16.end = strtoul(endptr+1, &endptr, 10);
	return U16_RANGE;
}

<INITIAL>{MAC} {
	if (!parse_mac(yylval.mac, make_token())) {
		return MAC;
	} else {
		LOG("err mac [%s] - ignore", make_token());
	}
}

<INITIAL>[a-zA-Z0-9][a-zA-Z0-9_]* {
	memset(yylval.text, 0, sizeof(yylval.text));
	strncpy(yylval.text, make_token(), sizeof(yylval.text)-1);
	return TEXT;
}

. { }

%%

void L_reset_buffer(void)
{
	YY_FLUSH_BUFFER;
}

KW_END

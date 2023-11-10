CM_BEGIN
%{
#include <linux/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "xlog.h"
#include "xtask.h"
#include "xutil.h"
#include "keyword.h"
#include "xconfig.h"

#define CLI_MAX_TOKEN 16
#define CLI_TOKEN_MAX_SIZE 0xff

struct xtask *current_task;
// static int command_error_token;

static void yyerror(const char *err_string) {
	LOG("%s - [%s]", err_string, current_line);

	// yyclearin;
	// yyerrok;
}

%}

%define parse.error verbose

// %define api.pure full

%union {
	__u32 number;
	__u8 boolean;
	__u8 mac[6];
	struct u16_range {
		__u16 begin;
		__u16 end;
	} ru16;
	struct ip_range {
		__u32 begin;
		__u32 end;
	} ipr;
	char text[0xff];
	pkt_type_t ptt;
}

%token SET LIST START STOP CLEAN ENTER QUIT ALL SAVE LOAD
%token SPORT DPORT DMAC SMAC QUEUE
%token SADDR DADDR INTERFACE CORE PACKET TIME
%token <text> TEXT
%token <number> NUMBER IP
%token <ru16> U16_RANGE
%token <ipr> IP_RANGE
%token <mac> MAC
%token <boolean> BOOL
%token <ptt> PTTV

%%

STAM : /*empty*/
	| STAM START_STAM
	| STAM STOP_STAM
	| STAM CLEAN_STAM
	| STAM SET_STAM
	| STAM LIST_STAM
	| STAM ENTER_STAM
	| STAM QUIT_STAM
	| STAM SAVE_STAM
	| STAM LOAD_STAM
	| error { YYABORT; }
	;

START_STAM : CLI_DEFINE_2(START) {
		UNSET_VIEW([[ xtask_start(0); ]])
	}
	| CLI_DEFINE_2(START TIME [NUMBER]) {
		UNSET_VIEW([[ xtask_start($3); ]])
	}
	;

STOP_STAM : CLI_DEFINE_2(STOP) {
		UNSET_VIEW()
	}
	;

SAVE_STAM : CLI_DEFINE_2(SAVE) {
		UNSET_VIEW([[ L_ins_save(DEFAULT_XTASK_CONFIG_SAVE_FILE); ]])
	}
	| CLI_DEFINE_2(SAVE [TEXT]) {
		UNSET_VIEW([[ L_ins_save($2); ]])
	}
	;

LOAD_STAM : CLI_DEFINE_2(LOAD) {
		UNSET_VIEW([[ L_ins_load(DEFAULT_XTASK_CONFIG_SAVE_FILE); ]])
	}
	| CLI_DEFINE_2(LOAD [TEXT]) {
		UNSET_VIEW([[ L_ins_load($2); ]])
	}
	;

CLEAN_STAM : CLI_DEFINE_1(CLEAN) {
		SET_VIEW([[
			xtask_remove(current_task);
			current_task = NULL;
		]])
	}
	| CLI_DEFINE_2(CLEAN ALL) {
		UNSET_VIEW([[xtask_cleanup();]])
	}
	| CLI_DEFINE_2(CLEAN INTERFACE [TEXT] QUEUE [NUMBER]) {
		UNSET_VIEW([[xtask_remove(xtask_lookup($3, $5));]])
	}
	;

QUIT_STAM : CLI_DEFINE_3(QUIT) {
		UNSET_VIEW([[exit(0);]],[[current_task = NULL;]])
	}
	;

SET_STAM : CLI_DEFINE_1(SET SMAC [MAC]) {
		SET_VIEW([[
			memcpy(current_task->smac, $3, sizeof(current_task->smac));
			TASK_SET(current_task, TASK_F_SMAC);
		]])
	}
	| CLI_DEFINE_1(SET DMAC [MAC]) {
		SET_VIEW([[
			memcpy(current_task->dmac, $3, sizeof(current_task->smac));
			TASK_SET(current_task, TASK_F_DMAC);
		]]);
	}
	| CLI_DEFINE_1(SET SADDR [IP_RANGE]) {
		SET_VIEW([[
			current_task->src_begin = $3.begin;
			current_task->src_end = $3.end;
			TASK_SET(current_task, TASK_F_SRC);
		]])
	}
	| CLI_DEFINE_1(SET SADDR [IP]) {
		SET_VIEW([[
			current_task->src_begin = $3;
			current_task->src_end = $3;
			TASK_SET(current_task, TASK_F_SRC);
		]])
	}
	| CLI_DEFINE_1(SET DADDR [IP]) {
		SET_VIEW([[
			current_task->dest = $3;
			TASK_SET(current_task, TASK_F_DST);
		]])
	}
	| CLI_DEFINE_1(SET CORE [NUMBER]) {
		SET_VIEW([[
			current_task->core_id = $3;
			TASK_SET(current_task, TASK_F_CORE);
		]])
	}
	| CLI_DEFINE_1(SET SPORT [U16_RANGE]) {
		SET_VIEW([[
			current_task->sport_begin = htons($3.begin);
			current_task->sport_end = htons($3.end);
			if (current_task->sport_end < current_task->sport_begin) {
				SWAP16(current_task->sport_end, current_task->sport_begin);
			}
			TASK_SET(current_task, TASK_F_SPORT);
		]])
	}
	| CLI_DEFINE_1(SET SPORT [NUMBER]) {
		SET_VIEW([[
			__u16 x = (__u16)$3;
			current_task->sport_begin = htons(x);
			current_task->sport_end = current_task->sport_begin;
			TASK_SET(current_task, TASK_F_SPORT);
		]])
	}
	| CLI_DEFINE_1(SET DPORT [NUMBER]) {
		SET_VIEW([[
			current_task->dport = htons($3);
			TASK_SET(current_task, TASK_F_DPORT);
		]])
	}
	| CLI_DEFINE_1(SET PACKET [PTTV]) {
		SET_VIEW([[ current_task->pkt_type = $3;
			TASK_SET(current_task, TASK_F_PKT_TYPE);
		]])
	}
	| CLI_DEFINE_1(SET TIME [NUMBER]) {
		SET_VIEW([[
			current_task->time = $3;
			TASK_SET(current_task, TASK_F_TIME);
		]])
	}
	;

LIST_STAM : CLI_DEFINE_3(LIST) {
		SET_VIEW([[ xtask_list (current_task); ]], [[xtask_list_outline();]])
	}
	;

ENTER_STAM : CLI_DEFINE_2(ENTER INTERFACE [TEXT] QUEUE [NUMBER]) {
		SET_VIEW([[ LOG("already in task set view"); ]], [[current_task = xtask_get($3, $5);]])
	}
	;

%%

SET_CLI_TABLE();




void Y_reset(void)
{
	
	// command_error_token = 0;
}

static char *Y_command_fetch_all(void) 
{
	UNSET_VIEW([[
		for (int i = 0; unset_command_table[i].command; ++i) {
			puts(unset_command_table[i].command);
		}
		]],
		[[
		for (int i = 0; set_command_table[i].command; ++i) {
			puts(set_command_table[i].command);
		}
		]])

	return NULL;
}

static void Y_make_token(char *tokens)
{
	char *save;
	char *token;
	char * line;
	int i = 0;

	line = XSTRDUP(rl_line_buffer);

	token = strtok_r(line, " ", &save);
	while (token) {
		strncpy(tokens + i * CLI_TOKEN_MAX_SIZE, token, CLI_TOKEN_MAX_SIZE-1);
		i++;
		token = strtok_r(NULL, " ", &save);
	}
	tokens[i * 0xff] = 0;

	XFREE(line);
}

static int Y_command_match_token(char *tokens, int index)
{
	struct command_item *table;
	UNSET_VIEW(table=unset_command_table;, table=set_command_table;)

	puts("");
	for (; table[index].command; ++index) {
		for (int i = 0; tokens[i * CLI_TOKEN_MAX_SIZE] != 0; ++i) {
			if (table[index].help[i] == NULL) {
				goto next;
			}
			if (table[index].help[i][0] == '[') {
				continue;
			}
			if (strncmp(tokens + i * CLI_TOKEN_MAX_SIZE, table[index].help[i], strlen(tokens + i * CLI_TOKEN_MAX_SIZE))) {
				goto next;
			}
		}
		puts(table[index].command);
next:
	}

	rl_forced_update_display();

	return 0;
}

static int Y_command_completion_match (int count, int key)
{
	int index;
	char tokens[CLI_MAX_TOKEN * CLI_TOKEN_MAX_SIZE];

	index = 0;
	if (*rl_line_buffer == 0) {
		puts("");
		Y_command_fetch_all();
		rl_forced_update_display();
		return 0;
	}
	Y_make_token((char*)tokens);

	return Y_command_match_token((char*)tokens, index);
}

int main(int argc, char **argv)
{
	rl_initialize();

	rl_bind_key('\t', Y_command_completion_match);

	while(1) {
		if (yyparse() == 0 && current_line) {
			add_history(current_line);
		}
		XFREE_CONST_PTR(current_line);
		L_reset_buffer();
	}

	return 0;
}

CM_END
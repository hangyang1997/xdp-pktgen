CM_BEGIN
%{
#include <linux/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <readline/history.h>
#include "xlog.h"
#include "xtask.h"
#include "xutil.h"
#include "keyword.h"
#include "xconfig.h"

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

%token SET LIST START STOP CLEAN ENTER QUITS ALL SAVE LOAD
%token SPORT DPORT DMAC SMAC QUEUE
%token SIP DIP IFNAME CORE PKTT TIME
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
	| STAM LSIT_STAM
	| STAM ENTER_STAM
	| STAM QUIT_STAM
	| STAM SAVE_STAM
	| STAM LOAD_STAM
	| error { YYABORT; }
	;

START_STAM : START {
		UNSET_VIEW([[ xtask_start(0); ]])
	}
	| START TIME NUMBER {
		UNSET_VIEW([[ xtask_start($3); ]])
	}
	;

STOP_STAM : STOP {
		UNSET_VIEW()
	}
	;

SAVE_STAM : SAVE {
		UNSET_VIEW([[ L_ins_save(DEFAULT_XTASK_CONFIG_SAVE_FILE); ]])
	}
	| SAVE TEXT {
		UNSET_VIEW([[ L_ins_save($2); ]])
	}
	;

LOAD_STAM : LOAD {
		UNSET_VIEW([[ L_ins_load(DEFAULT_XTASK_CONFIG_SAVE_FILE); ]])
	}
	| LOAD TEXT {
		UNSET_VIEW([[ L_ins_load($2); ]])
	}
	;

CLEAN_STAM : CLEAN {
		SET_VIEW([[
			xtask_remove(current_task);
			current_task = NULL;
		]])
	}
	| CLEAN ALL {
		UNSET_VIEW([[xtask_cleanup();]])
	}
	| CLEAN IFNAME TEXT QUEUE NUMBER {
		UNSET_VIEW([[xtask_remove(xtask_lookup($3, $5));]])
	}
	;

QUIT_STAM : QUITS {
		UNSET_VIEW([[exit(0);]],[[current_task = NULL;]])
	}
	;

SET_STAM : SET SMAC MAC {
		SET_VIEW([[
			memcpy(current_task->smac, $3, sizeof(current_task->smac));
			TASK_SET(current_task, TASK_F_SMAC);
		]])
	}
	| SET DMAC MAC {
		SET_VIEW([[
			memcpy(current_task->dmac, $3, sizeof(current_task->smac));
			TASK_SET(current_task, TASK_F_DMAC);
		]]);
	}
	| SET SIP IP_RANGE {
		SET_VIEW([[
			current_task->src_begin = $3.begin;
			current_task->src_end = $3.end;
			TASK_SET(current_task, TASK_F_SRC);
		]])
	}
	| SET SIP IP {
		SET_VIEW([[
			current_task->src_begin = $3;
			current_task->src_end = $3;
			TASK_SET(current_task, TASK_F_SRC);
		]])
	}
	| SET DIP IP {
		SET_VIEW([[
			current_task->dest = $3;
			TASK_SET(current_task, TASK_F_DST);
		]])
	}
	| SET CORE NUMBER {
		SET_VIEW([[
			current_task->core_id = $3;
			TASK_SET(current_task, TASK_F_CORE);
		]])
	}
	| SET SPORT U16_RANGE {
		SET_VIEW([[
			current_task->sport_begin = htons($3.begin);
			current_task->sport_end = htons($3.end);
			if (current_task->sport_end < current_task->sport_begin) {
				SWAP16(current_task->sport_end, current_task->sport_begin);
			}
			TASK_SET(current_task, TASK_F_SPORT);
		]])
	}
	| SET SPORT NUMBER {
		SET_VIEW([[
			__u16 x = (__u16)$3;
			current_task->sport_begin = htons(x);
			current_task->sport_end = current_task->sport_begin;
			TASK_SET(current_task, TASK_F_SPORT);
		]])
	}
	| SET DPORT NUMBER {
		SET_VIEW([[
			current_task->dport = htons($3);
			TASK_SET(current_task, TASK_F_DPORT);
		]])
	}
	| SET PKTT PTTV {
		SET_VIEW([[ current_task->pkt_type = $3;
			TASK_SET(current_task, TASK_F_PKT_TYPE);
		]])
	}
	| SET TIME NUMBER {
		SET_VIEW([[
			current_task->time = $3;
			TASK_SET(current_task, TASK_F_TIME);
		]])
	}
	;

LSIT_STAM : LIST {
		SET_VIEW([[ xtask_list (current_task); ]], [[xtask_list_outline();]])
	}
	;

ENTER_STAM : ENTER IFNAME TEXT QUEUE NUMBER {
		SET_VIEW([[ LOG("already in task set view"); ]], [[current_task = xtask_get($3, $5);]])
	}
	;

%%

void Y_reset(void)
{
	// command_error_token = 0;
}

int main(int argc, char **argv)
{
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

m4_divert(-1)m4_dnl

m4_define(`CM_DIVERT', 1)
m4_define(`KW_DIVERT', 2)
m4_define(`CM_HELP_SET', 3)
m4_define(`CM_HELP_UNSET', 4)



m4_define(`m4_itera', `m4_ifelse($#, 1, [[m4_iter($1)]], [[m4_iter($1)m4_itera(m4_shift($@))]])')
m4_define(`m4_iterator', `m4_define([[m4_iter]], m4_defn([[$1]]))m4_itera(m4_shift($@))')

m4_define(`SET_VIEW', `m4_ifelse($#, 2,
[[if (current_task != NULL) { $1 } else { $2 }]],
[[if (current_task != NULL) { $1 } else {LOG("please enter set view"); YYABORT; }]])')

m4_define(`UNSET_VIEW', `m4_ifelse($#, 2,
[[if (current_task == NULL) { $1 } else { $2 }]],
[[if (current_task == NULL) { $1 } else {LOG("please quit set view"); YYABORT; }]])')

m4_define(`__KWLOAD',`
	if (!strncmp(line, $1, strlen($1))) { return 1; }
')

# key_word_load_check
m4_define(`KW_LOAD_CHECK', `static int key_word_load_check (const char *line) {
	m4_iterator([[__KWLOAD]], $@)
	return 0;
}')

m4_define(`quote', `[[ "]]$1[["]]')

m4_define(`quotes', `"$1"m4_iterator([[quote]], m4_shift($@))')

m4_define(`__CM_CLI_CMD', `m4_divert($1)
	{ {m4_translit($2, [[ ]], [[,]])}, {m4_translit(quotes(m4_translit($3, [[ ]], [[,]])), [[ ]], [[,]])}, [["]]m4_translit($4, [[A-Z]], [[a-z]])[["]]},
	CM_BEGIN
')


m4_define(`CLI_DEFINE_1', `m4_translit($1, [[[]]], [[]])'
`__CM_CLI_CMD([[CM_HELP_SET]], m4_translit($1, [[[]]], [[]]), m4_translit($1, [[A-Z]], [[a-z]]), [[$1]])')

m4_define(`CLI_DEFINE_2', `m4_translit($1, [[[]]], [[]])'
`__CM_CLI_CMD([[CM_HELP_UNSET]], m4_translit($1, [[[]]], [[]]), m4_translit($1, [[A-Z]], [[a-z]]), [[$1]])')

m4_define(`CLI_DEFINE_3', `m4_translit($1, [[[]]], [[]])'
`__CM_CLI_CMD([[CM_HELP_UNSET]], m4_translit($1, [[[]]], [[]]), m4_translit($1, [[A-Z]], [[a-z]]), [[$1]])'
`__CM_CLI_CMD([[CM_HELP_SET]], m4_translit($1, [[[]]], [[]]), m4_translit($1, [[A-Z]], [[a-z]]), [[$1]])')

m4_define(`SET_CLI_TABLE', `
struct command_item {
	int token[CLI_MAX_TOKEN];
	const char *help[CLI_MAX_TOKEN];
	const char *command;
};
__attribute__((unused)) static struct command_item set_command_table[] = {
	m4_undivert(CM_HELP_SET)
	{{0}, {NULL}, NULL}
};

__attribute__((unused)) static struct command_item unset_command_table[] = {
	m4_undivert(CM_HELP_UNSET)
	{{0}, {NULL}, NULL}
}

')

m4_define(`CM_BEGIN', `m4_divert(CM_DIVERT)m4_dnl')
m4_define(`CM_END', `m4_undivert(CM_DIVERT)m4_dnl')

m4_define(`KW_BEGIN', `m4_divert(KW_DIVERT)m4_dnl')
m4_define(`KW_END', `m4_undivert(KW_DIVERT)m4_dnl')

m4_changequote([[,]])

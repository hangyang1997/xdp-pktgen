#ifndef __KEYWORD_H
#define __KEYWORD_H

extern int yylex(void);
extern void Y_reset(void);

extern void L_ins_save(const char *filename);
extern void L_ins_load(const char *filename);
extern void L_reset_buffer(void);

extern const char *current_line;

#endif

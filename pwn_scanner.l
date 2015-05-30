%option c++ yyclass="pwn_scanner" outfile="pwn_scanner.cpp"
%option stack noyywrap yylineno 8bit
%{ 
/* $Id: pwn_scanner.l,v 1.25 2015/05/18 23:24:47 ist175551 Exp $ */

// make relevant includes before including the parser's tab file
#include <string>
#include <cdk/ast/sequence_node.h>
#include <cdk/ast/expression_node.h>
#include "pwn_scanner.h"
#include "pwn_parser.tab.h"

// don't change this
#define yyerror LexerError
%}

FDIGIT [1-9]
DIGIT  [0-9]
HEXAD  [0-9a-fA-F]
EXP    [eE][+-]?{INT}+
INT    {FDIGIT}{DIGIT}*
SPACE  [ \t\n\r]
IDENTIFIER [A-Za-z_][A-Za-z0-9_]*

%x X_STRING X_COMMENT X_SPECIAL_CHAR X_CHAR

%%
       //{ set_debug(1); }
<X_SPECIAL_CHAR>n                        yy_pop_state(); /**yylval.s += std::string(1,10);*/
<X_SPECIAL_CHAR>r                        yy_pop_state(); /**yylval.s += std::string(1,13);*/
<X_SPECIAL_CHAR>t                        yy_pop_state(); /**yylval.s += std::string(1,9);*/
<X_SPECIAL_CHAR>[\"\\]                   yy_pop_state(); *yylval.s += std::string(1,(int)*yytext);
<X_SPECIAL_CHAR>{HEXAD}{HEXAD}?         { yy_pop_state();
                                          long a = strtol(yytext, nullptr, 16);
                                          if (a != 0x0a && a != 0x0d && a != 0x20 && a != 0x09)
                                             *yylval.s += std::string(1, a);
                                         }
<X_SPECIAL_CHAR>.|\n                     yyerror("Invalid special character");

\"                                 	yy_push_state(X_STRING); yylval.s = new std::string("");
<X_STRING>\"                       	yy_pop_state(); return tSTRING;
<X_STRING>\\                            yy_push_state(X_SPECIAL_CHAR);
<X_STRING>\\\"                     	*yylval.s += yytext + 1;
<X_STRING>.                        	*yylval.s += yytext;
<X_STRING>\n                       	yyerror("newline in string");

"/*"                               	yy_push_state(X_COMMENT);
<X_COMMENT>"/*"                    	yy_push_state(X_COMMENT);
<X_COMMENT>"*/"                    	yy_pop_state();
<X_COMMENT>.|\n                    	; /* ignore comments */

"//".*$                            	; /* ignore comments */

 /* Keywords */ 
"local"                            	return tLOCAL;
"import"                           	return tIMPORT;

"next"                                  return tNEXT;
"stop"                                  return tSTOP;

"return"                           	return tRETURN;

"noob"                            	return tNOOB;

"repeat"                           	return tREPEAT;

"if"                               	return tIF;
"else"                             	return tELSE;


 /* Expressions  */
">="                                    return tGE; 
"<="                                    return tLE; 
"=="                                    return tEQ; 
"<>"                                    return tNE; 

[-()<>=+*/%;{}.#%$?!~&|@,]              return *yytext;

{IDENTIFIER}                            yylval.s = new std::string(yytext); return tIDENTIFIER;

 /* Numbers */
0[xX]{HEXAD}+                           yylval.i = strtol(&yytext[2], nullptr, 16); return tHEXA;


{INT}{EXP}                              yylval.d = strtod(yytext, nullptr); return tREALN;
{INT}\.{INT}{EXP}                       yylval.d = strtod(yytext, nullptr); return tREALN;
{INT}\.{INT}                            yylval.d = strtod(yytext, nullptr); return tREALN;
{INT}\.{EXP}                            yylval.d = strtod(yytext, nullptr); return tREALN;
{INT}\.                                 yylval.d = strtod(yytext, nullptr); return tREALN;
\.{INT}                                 yylval.d = strtod(yytext, nullptr); return tREALN;
\.{INT}{EXP}                            yylval.d = strtod(yytext, nullptr); return tREALN;



{INT}|0                                   yylval.i = strtol(yytext, nullptr, 10); return tINTEGER;
          
{SPACE}+                                ; /* ignore whitespace */

.                                        yyerror("Unknown character");

%%
// Very, very dirty hack: flex is a mess generating C++ scanners.
int pwn_scanner::yywrap() { return 1; }
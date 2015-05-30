%{
// $Id: pwn_parser.y,v 1.32 2015/05/20 09:34:14 ist175551 Exp $
//-- don't change *any* of these: if you do, you'll break the compiler.

#include <string>
#include <map>
#include <cdk/compiler.h>
#include "ast/all.h"
#define LINE       compiler->scanner()->lineno()
#define yylex()    compiler->scanner()->scan()
#define yyerror(s) compiler->scanner()->error(s)
#define YYPARSE_PARAM_TYPE std::shared_ptr<cdk::compiler>
#define YYPARSE_PARAM      compiler
//-- don't change *any* of these --- END!

static std::map< std::string, cdk::expression_node* > vars;
%}

%union {
  int                   i;            /* integer value */
  long double           d;            /* real value */
  std::string           *s;           /* symbol name or string literal */
  bool                  local;
  cdk::basic_node       *node;        /* node pointer */
  cdk::sequence_node    *sequence;
  cdk::expression_node  *expression;  /* expression nodes */
  pwn::block_node       *block;
  pwn::lvalue_node      *lvalue;
  basic_type            *basic;
  cdk::integer_node	*integer;
};

%token <i> tINTEGER tHEXA
%token <s> tIDENTIFIER tSTRING
%token <d> tREALN
%token tREPEAT tIF
%token tNEXT tSTOP tRETURN tNOOB
%token tLOCAL tIMPORT

%nonassoc tIFX
%nonassoc tELSE

%right '='
%left '&' '|'
%left tGE tLE tEQ tNE
%left '+' '-'
%left '/' 
%left '#' '$' '%' '*'
%left '<' '>'
%left '?'
%nonassoc tUNARY
%nonassoc ex

%type <node> program decl var_decl func_decl func_arg instr instr_cond instr_iter
%type <sequence> declrs exprs func_args instrs
%type <local> scope
%type <s> stringa
%type <expression> expr literal
%type <lvalue> lval
%type <basic> type
%type <block> block body
%type <integer> litint

%{
//-- The rules below will be included in yyparse, the main parsing function.
%}
%%

program : declrs { compiler->ast($1); }
        ;

declrs : decl         { $$ = new cdk::sequence_node(LINE, $1); }
       | declrs decl  { $$ = new cdk::sequence_node(LINE, $2, $1); }
       ;

decl : var_decl           { $$ = $1; }
     | func_decl          { $$ = $1; }
     ;

type : '#'           { $$ = new basic_type(4, basic_type::TYPE_INT); }
     | '%'           { $$ = new basic_type(8, basic_type::TYPE_DOUBLE); }
     | '$'           { $$ = new basic_type(4, basic_type::TYPE_STRING); }
     | '*'           { $$ = new basic_type(4, basic_type::TYPE_POINTER); }
     ;

scope : tLOCAL                                         { $$ = true; }
      | tIMPORT                                        { $$ = false; }
      ;
     
var_decl : scope type tIDENTIFIER ';'                     { $$ = new pwn::var_decl_node(LINE, false, $1, !$1, $2, *$3, nullptr); }
         | scope type tIDENTIFIER '=' expr ';'            { $$ = new pwn::var_decl_node(LINE, false, $1, !$1, $2, *$3, $5); }
         | type tIDENTIFIER ';'                           { $$ = new pwn::var_decl_node(LINE, false, false, false, $1, *$2, nullptr); }
         | type tIDENTIFIER '=' expr ';'                  { $$ = new pwn::var_decl_node(LINE, false, false, false, $1, *$2, $4); }
         
         | scope '<' type '>' tIDENTIFIER ';'                     { $$ = new pwn::var_decl_node(LINE, true, $1, !$1, $3, *$5, nullptr); }
         | scope '<' type '>' tIDENTIFIER '=' expr ';'            { $$ = new pwn::var_decl_node(LINE, true, $1, !$1, $3, *$5, $7); }
         | '<' type '>' tIDENTIFIER ';'                           { $$ = new pwn::var_decl_node(LINE, true, false, false, $2, *$4, nullptr); }
         | '<' type '>' tIDENTIFIER '=' expr ';'                  { $$ = new pwn::var_decl_node(LINE, true, false, false, $2, *$4, $6); }
         ;
          
func_decl : scope type tIDENTIFIER '(' func_args ')'              { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, $5, nullptr, nullptr); }
          | scope type tIDENTIFIER '(' ')'                        { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, nullptr, nullptr, nullptr); }
          | scope '!' tIDENTIFIER '(' func_args ')'              { $$ = new pwn::function_decl_node(LINE, $1, !$1, nullptr, *$3, $5, nullptr, nullptr); }
          | scope '!' tIDENTIFIER '(' ')'                        { $$ = new pwn::function_decl_node(LINE, $1, !$1, nullptr, *$3, nullptr, nullptr, nullptr); }

          | type tIDENTIFIER '(' func_args ')'                    { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, $4, nullptr, nullptr); }
          | type tIDENTIFIER '(' ')'                              { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, nullptr, nullptr, nullptr); }
          | '!' tIDENTIFIER '(' func_args ')'                    { $$ = new pwn::function_decl_node(LINE, false, false, nullptr, *$2, $4, nullptr, nullptr); }
          | '!' tIDENTIFIER '(' ')'                              { $$ = new pwn::function_decl_node(LINE, false, false, nullptr, *$2, nullptr, nullptr, nullptr); }
          
          | scope type tIDENTIFIER '(' func_args ')' '=' literal  { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, $5, $8, nullptr); }
          | scope type tIDENTIFIER '(' ')' '=' literal            { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, nullptr, $7, nullptr); }
          
          | type tIDENTIFIER '(' func_args ')' '=' literal        { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, $4, $7, nullptr); }
          | type tIDENTIFIER '(' ')' '=' literal                  { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, nullptr, $6, nullptr); }
          
          | scope type tIDENTIFIER '(' func_args ')' body         { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, $5, nullptr, $7); }
          | scope type tIDENTIFIER '(' ')' body                   { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, nullptr, nullptr, $6);}
          | scope '!' tIDENTIFIER '(' func_args ')' body         { $$ = new pwn::function_decl_node(LINE, $1, !$1, nullptr, *$3, $5, nullptr, $7); }
          | scope '!' tIDENTIFIER '(' ')' body                   { $$ = new pwn::function_decl_node(LINE, $1, !$1, nullptr, *$3, nullptr, nullptr, $6); }

          | type tIDENTIFIER '(' func_args ')' body               { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, $4, nullptr, $6); }
          | type tIDENTIFIER '(' ')' body                         { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, nullptr, nullptr, $5); }
          | '!' tIDENTIFIER '(' func_args ')' body               { $$ = new pwn::function_decl_node(LINE, false, false, nullptr, *$2, $4, nullptr, $6); }
          | '!' tIDENTIFIER '(' ')' body                         { $$ = new pwn::function_decl_node(LINE, false, false, nullptr, *$2, nullptr, nullptr, $5); }
          
          | scope type tIDENTIFIER '(' func_args ')' '=' literal  body   { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, $5, $8, $9); }
          | scope type tIDENTIFIER '(' ')' '=' literal body              { $$ = new pwn::function_decl_node(LINE, $1, !$1, $2, *$3, nullptr, $7, $8); }

          | type tIDENTIFIER '(' func_args ')' '=' literal body          { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, $4, $7, $8); }
          | type tIDENTIFIER '(' ')' '=' literal body                    { $$ = new pwn::function_decl_node(LINE, false, false, $1, *$2, nullptr, $6, $7); }
          ;
          
func_args : func_arg                      { $$ = new cdk::sequence_node(LINE, $1); }
          | func_args ',' func_arg        { $$ = new cdk::sequence_node(LINE, $3, $1); }
          ;
      
func_arg : type tIDENTIFIER               { $$ = new pwn::var_decl_node(LINE, false, true, false, $1, *$2, nullptr); delete($2); }
         ;

body : block                              { $$ = $1; }
     ;

block : '{' '}'                           { $$ = new pwn::block_node(LINE, nullptr, nullptr);; }
      | '{' declrs '}'                    { $$ = new pwn::block_node(LINE, $2, nullptr); }
      | '{' instrs '}'                    { $$ = new pwn::block_node(LINE, nullptr, $2); }
      | '{' declrs instrs '}'             { $$ = new pwn::block_node(LINE, $2, $3); }
      ;
      
instrs : instr                            { $$ = new cdk::sequence_node(LINE, $1); }
       | instrs instr                     { $$ = new cdk::sequence_node(LINE, $2, $1); }
       ;
       
instr : expr ';'                          { $$ = new pwn::evaluation_node(LINE, $1); }
      | expr '!'                          { $$ = new pwn::print_node(LINE, $1); }
      | expr '!''!'                       { $$ = new pwn::println_node(LINE, $1); }
      | tSTOP litint ';'                  { $$ = new pwn::stop_node(LINE, $2); }
      | tSTOP ';'                         { $$ = new pwn::stop_node(LINE, new cdk::integer_node(LINE, 1)); }
      | tNEXT litint ';'                  { $$ = new pwn::next_node(LINE, $2); }
      | tNEXT ';'                         { $$ = new pwn::next_node(LINE, new cdk::integer_node(LINE, 1)); }
      | tRETURN                           { $$ = new pwn::return_node(LINE); }
      | instr_cond                        { $$ = $1; }
      | instr_iter                        { $$ = $1; }
      | block                             { $$ = $1; }
      ;

instr_cond : tIF '(' expr ')' instr %prec tIFX   { $$ = new cdk::if_node(LINE, $3, $5); }
           | tIF '(' expr ')' instr tELSE instr  { $$ = new cdk::if_else_node(LINE, $3, $5, $7); }
           ;

instr_iter : tREPEAT '(' exprs ';' exprs ';' exprs ')' instr       { $$ = new pwn::repeat_node(LINE, $3, $5, $7, $9); }
           | tREPEAT '(' exprs ';' exprs ';'       ')' instr       { $$ = new pwn::repeat_node(LINE, $3, $5, nullptr, $8); }
           | tREPEAT '(' exprs ';'       ';'       ')' instr       { $$ = new pwn::repeat_node(LINE, $3, nullptr, nullptr, $7); }
           | tREPEAT '(' exprs ';'       ';' exprs ')' instr       { $$ = new pwn::repeat_node(LINE, $3, nullptr, $6, $8); }
           | tREPEAT '('       ';' exprs ';' exprs ')' instr       { $$ = new pwn::repeat_node(LINE, nullptr, $4, $6, $8); }
           | tREPEAT '('       ';' exprs ';'       ')' instr       { $$ = new pwn::repeat_node(LINE, nullptr, $4, nullptr, $7); }
           | tREPEAT '('       ';'       ';' exprs ')' instr       { $$ = new pwn::repeat_node(LINE, nullptr, nullptr, $5, $7); }
           | tREPEAT '('       ';'       ';'       ')' instr       { $$ = new pwn::repeat_node(LINE, nullptr, nullptr, nullptr, $6); }
           ;   
           
exprs : expr                         { $$ = new cdk::sequence_node(LINE, $1); }
      | exprs ',' expr               { $$ = new cdk::sequence_node(LINE, $3, $1); }
      ;
      
expr : literal                                                       { $$ = $1; }
//     | '*' lval_id %prec tUNARY                                      { }
     | '+' expr    %prec tUNARY                                      { $$ = new pwn::identity_node(LINE, $2); }
     | '-' expr    %prec tUNARY                                      { $$ = new cdk::neg_node(LINE, $2); }
     | '~' expr    %prec tUNARY                                      { $$ = new pwn::not_node(LINE, $2); }
     | expr '+' expr                                                 { $$ = new cdk::add_node(LINE, $1, $3); }
     | expr '-' expr                                                 { $$ = new cdk::sub_node(LINE, $1, $3); }
     | expr '*' expr                                                 { $$ = new cdk::mul_node(LINE, $1, $3); }
     | expr '/' expr                                                 { $$ = new cdk::div_node(LINE, $1, $3); }
     | expr '%' expr                                                 { $$ = new cdk::mod_node(LINE, $1, $3); }
     | expr '<' expr                                                 { $$ = new cdk::lt_node(LINE, $1, $3); }
     | expr '>' expr                                                 { $$ = new cdk::gt_node(LINE, $1, $3); }
     | expr tGE expr                                                 { $$ = new cdk::ge_node(LINE, $1, $3); }
     | expr tLE expr                                                 { $$ = new cdk::le_node(LINE, $1, $3); }
     | expr tNE expr                                                 { $$ = new cdk::ne_node(LINE, $1, $3); }
     | expr tEQ expr                                                 { $$ = new cdk::eq_node(LINE, $1, $3); }
     | expr '&' expr                                                 { $$ = new pwn::and_node(LINE, $1, $3); }
     | expr '|' expr                                                 { $$ = new pwn::or_node(LINE, $1, $3);}
     | '(' expr ')'                                                  { $$ = $2; }
     | '[' expr ']'                                                  { $$ = $2; }
     | lval                                                          { $$ = new pwn::rvalue_node(LINE, $1); }
     | lval '?' %prec tUNARY                                         { $$ = new pwn::qmark_node(LINE, $1); }
     | '@'                                                           { $$ = new pwn::read_node(LINE); }
     | tIDENTIFIER '(' exprs ')'                                     { $$ = new pwn::function_call_node(LINE, *$1, $3); }
     | tIDENTIFIER '(' ')'                                           { $$ = new pwn::function_call_node(LINE, *$1, nullptr); }
     | lval '=' expr        	                                     { $$ = new pwn::assignment_node(LINE, $1, $3); }
     ;
     
lval : tIDENTIFIER                                                { $$ = new pwn::var_node(LINE, *$1); }
     ;
     
litint : tINTEGER                  { $$ = new cdk::integer_node(LINE, $1); }
       | tHEXA                     { $$ = new cdk::integer_node(LINE, $1); }
       ;    

literal : litint                            { $$ = $1; }
        | stringa                           { $$ = new cdk::string_node(LINE, $1);  }
        | tREALN                            { $$ = new cdk::double_node(LINE, $1); }
        | tNOOB                             { $$ = new pwn::noob_node(LINE); }
        ;   
        
stringa : tSTRING                           { $$ = $1; }
        | stringa tSTRING %prec ex          { $$ = new std::string(*$1 + *$2); delete($1); delete($2); }
        ;
%%

/*

%type <node> decl var func stmt stmt_cond stmt_iter program2 
%type <block> body block
%type <sequence> list declrs exprsi exprs vars args program
%type <basic> type
%type <expression> expr literal func_literal var_expr
%type <local> scope
%type <s> stringa
%type <i> litint
%type <lvalue> lval_id lval

%%

program2 : program                                                   { compiler->ast($1); }
         ;

program :                                                            { $$ = new cdk::sequence_node(LINE, nullptr); }
        | decl                                                       { $$ = new cdk::sequence_node(LINE, $1); }
        | program decl                                               { $$ = new cdk::sequence_node(LINE, $2, $1); }
        ;

decl : var ';'                                                       { $$ = $1; }
     | func                                                          { $$ = $1; }
     ;

var : scope type tIDENTIFIER var_expr                                { $$ = new pwn::var_decl_node(LINE, $1, $2, $3, $4); }
    | type tIDENTIFIER var_expr                                      { $$ = new pwn::var_decl_node(LINE, true, $1, $2, $3); }
    ;

var_expr :                                                           { $$ = nullptr; }
         | '=' expr                                                  { $$ = $2; }
         ;

func : scope type tIDENTIFIER '(' args ')' func_literal body         { $$ = new pwn::function_decl_node(LINE, $1, $2, $3, $5, $7, $8); }
     | type tIDENTIFIER '(' args ')' func_literal body               { $$ = new pwn::function_decl_node(LINE, true, $1, $2, $4, $6, $7); }
     | scope '!' tIDENTIFIER '(' args ')' func_literal body          { $$ = new pwn::function_decl_node(LINE, $1, nullptr, $3, $5, $7, $8); }
     | '!' tIDENTIFIER '(' args ')' func_literal body                { $$ = new pwn::function_decl_node(LINE, true, nullptr, $2, $4, $6, $7); }
     ;

scope : tLOCAL                                                       { $$ = true; }
      | tIMPORT                                                      { $$ = false; }
      ;

type : '#'                                                           { $$ = new basic_type(4, basic_type::TYPE_INT); }
     | '%'                                                           { $$ = new basic_type(8, basic_type::TYPE_DOUBLE); }
     | '$'                                                           { $$ = new basic_type(4, basic_type::TYPE_STRING); }
     | '*'                                                           { $$ = new basic_type(4, basic_type::TYPE_POINTER); }
     | '<' type '>'                                                  { $$ = $2; }
     ;

args :                                                               { $$ = nullptr; }
     | vars                                                          { $$ = $1; }
     ;

vars : var                                                           { $$ = new cdk::sequence_node(LINE, $1); }
     | vars ',' var                                                      { $$ = new cdk::sequence_node(LINE, $3, $1); }
     ;

func_literal :                                                       { $$ = nullptr; }
             | '=' literal                                           { $$ = $2; }
             ;

literal : tINTEGER                                                   { $$ = new cdk::integer_node(LINE, $1); }
        | stringa                                                    { $$ = new cdk::string_node(LINE, $1); }
        | tHEXA                                                      { $$ = new cdk::integer_node(LINE, $1); }
        | tREALN                                                     { $$ = new cdk::double_node(LINE, $1); }
        | tNOOB                                                      { $$ = new pwn::noob_node(LINE); }
        ;

body :                                                               { $$ = nullptr; }
     | block                                                         { $$ = $1; }
     ;

block : '{' '}'                                                      { $$ = nullptr; }
      | '{' declrs list '}'                                          { $$ = new pwn::block_node(LINE, new cdk::sequence_node(LINE, $2, $3)); }
      ;

declrs :                                                             { $$ = nullptr; }
       | decl declrs                                                 { $$ = new cdk::sequence_node(LINE, $1, $2); }
       ;

list : stmt                                                          { $$ = new cdk::sequence_node(LINE, $1); }
     | list stmt                                                     { $$ = new cdk::sequence_node(LINE, $2, $1); }
     ;

stmt : expr ';'                                                      { $$ = new pwn::evaluation_node(LINE, $1); }
     | expr '!'                                                      { $$ = new pwn::print_node(LINE, $1); }
     | expr '!''!'                                                   { $$ = new pwn::println_node(LINE, $1); }
     | tSTOP litint ';'                                              { $$ = new pwn::stop_node(LINE, $2); }
     | tNEXT litint ';'                                              { $$ = new pwn::next_node(LINE, $2); }
     | tRETURN                                                       { $$ = new pwn::return_node(LINE); }
     | stmt_cond                                                     { $$ = $1; }
     | stmt_iter                                                     { $$ = $1; }
     | block                                                         { $$ = $1; }
     ;

stmt_cond : tIF '(' expr ')' stmt %prec tIFX                         { $$ = new cdk::if_node(LINE, $3, $5); }
          | tIF '(' expr ')' stmt tELSE stmt                         { $$ = new cdk::if_else_node(LINE, $3, $5, $7); }
          ;

stmt_iter : tREPEAT '(' exprsi ';' exprsi ';' exprsi ')' stmt        { $$ = new pwn::repeat_node(LINE, $3, $5, $7, $9); }
          ;

exprsi :                                                             { $$ = nullptr; }
       | exprs                                                       { $$ = $1; }
       ;

litint :                                                             { $$ =  0; }
       | tINTEGER                                                    { $$ = $1; }
       ;

exprs : expr                                                         { $$ = new cdk::sequence_node(LINE, $1); }
      | exprs ',' expr                                               { $$ = new cdk::sequence_node(LINE, $3, $1); }
      ;
       
expr : literal                                                       { $$ = $1; }
     | '+' expr %prec tUNARY                                         { $$ = new pwn::identity_node(LINE, $2); }
     | '-' expr %prec tUNARY                                         { $$ = new cdk::neg_node(LINE, $2); }
     | '~' expr %prec tUNARY                                         { $$ = new pwn::not_node(LINE, $2); }
     | expr '+' expr                                                 { $$ = new cdk::add_node(LINE, $1, $3); }
     | expr '-' expr                                                 { $$ = new cdk::sub_node(LINE, $1, $3); }
     | expr '*' expr                                                 { $$ = new cdk::mul_node(LINE, $1, $3); }
     | expr '/' expr                                                 { $$ = new cdk::div_node(LINE, $1, $3); }
     | expr '%' expr                                                 { $$ = new cdk::mod_node(LINE, $1, $3); }
     | expr '<' expr                                                 { $$ = new cdk::lt_node(LINE, $1, $3); }
     | expr '>' expr                                                 { $$ = new cdk::gt_node(LINE, $1, $3); }
     | expr tGE expr                                                 { $$ = new cdk::ge_node(LINE, $1, $3); }
     | expr tLE expr                                                 { $$ = new cdk::le_node(LINE, $1, $3); }
     | expr tNE expr                                                 { $$ = new cdk::ne_node(LINE, $1, $3); }
     | expr tEQ expr                                                 { $$ = new cdk::eq_node(LINE, $1, $3); }
     | expr '&' expr                                                 { $$ = new pwn::and_node(LINE, $1, $3); }
     | expr '|' expr                                                 { $$ = new pwn::or_node(LINE, $1, $3);}
     | '(' expr ')'                                                  { $$ = $2; }
     
     | lval_id                                                       { $$ = new pwn::rvalue_node(LINE, $1); }
     | lval_id '=' expr                                              { $$ = new pwn::assignment_node(LINE, $1, $3); }
     | lval_id '?'                                                  { $$ = new pwn::qmark_node(LINE, $1); }
     | '@'                                                           { $$ = new pwn::read_node(LINE); }
     | lval_id '=' '[' litint ']'                                    { $$ = new pwn::memory_node(LINE, $1, $4); }
     | tIDENTIFIER '(' exprsi ')'                                    { $$ = new pwn::function_call_node(LINE, $1, $3); }
     ;
     
lval_id : tIDENTIFIER                                                { $$ = new pwn::var_node(LINE, $1); }
        | '*' tIDENTIFIER                                            { }
        | lval                                                       { $$ = $1; }
        ;

lval : lval_id '[' expr ']'                                          { $$ = new pwn::index_node(LINE, $1, $3); }


stringa : tSTRING                                                    { $$ = $1; }
        | stringa tSTRING                                            { $$ = new std::string(*$1 + *$2); delete($1); delete($2); }
%%*/
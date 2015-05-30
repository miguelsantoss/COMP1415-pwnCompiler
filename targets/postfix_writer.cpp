// $Id: postfix_writer.cpp,v 1.33 2015/05/20 10:37:40 ist175551 Exp $ -*- c++ -*-
#include <string>
#include <sstream>
#include "targets/type_checker.h"
#include "targets/postfix_writer.h"
#include "ast/all.h"  // all.h is automatically generated

//---------------------------------------------------------------------------
//     THIS IS THE VISITOR'S DEFINITION
//---------------------------------------------------------------------------

void pwn::postfix_writer::do_sequence_node(cdk::sequence_node * const node, int lvl) {
  for (size_t i = 0; i < node->size(); i++) {
    node->node(i)->accept(this, lvl);
  }
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_integer_node(cdk::integer_node * const node, int lvl) {
  if(_insidefunc)
    _pf.INT(node->value()); // push an integer
  else
    _pf.CONST(node->value());
}

void pwn::postfix_writer::do_double_node(cdk::double_node * const node, int lvl) {
  int lbl1;
  if (!_insidefunc) {
    _pf.RODATA();
    _pf.ALIGN();
    _pf.LABEL(mklbl(lbl1 = ++_lbl));
    _pf.DOUBLE(node->value());
    _pf.TEXT();
    _pf.ADDR(mklbl(lbl1));
  }
  else if (_insidefunc && !_args)
    _pf.RODATA();
    _pf.ALIGN();
    _pf.LABEL(mklbl(lbl1 = ++_lbl));
    _pf.DOUBLE(node->value());
    _pf.TEXT();
    _pf.ADDR(mklbl(lbl1));
    _pf.DLOAD();
}

void pwn::postfix_writer::do_string_node(cdk::string_node * const node, int lvl) {
  int lbl1;
  if (_args || !_insidefunc)
    _pf.STR(node->value());
  else {
    _pf.RODATA();
    _pf.ALIGN();
    _pf.LABEL(mklbl(lbl1 = ++_lbl));
    _pf.STR(node->value());
    _pf.TEXT();
    _pf.ALIGN();
    _pf.ADDR(mklbl(lbl1));
  }
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_neg_node(cdk::neg_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->argument()->accept(this, lvl); // determine the value
  if (node->type()->name() == basic_type::TYPE_DOUBLE)
    _pf.DNEG();
  if (node->type()->name() == basic_type::TYPE_INT)
    _pf.NEG(); // 2-complement
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_add_node(cdk::add_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  if (node->type()->name() == basic_type::TYPE_DOUBLE && (node->left()->type()->name() != node->type()->name() || node->right()->type()->name() != node->type()->name())) {
    if (node->left()->type()->name() != node->type()->name()) {
      node->left()->accept(this, lvl);
      _pf.I2D();
      node->right()->accept(this, lvl);
    }
    else {
      node->left()->accept(this, lvl);
      node->right()->accept(this, lvl);
      _pf.I2D();
    }
  }
  else if (node->type()->name() == basic_type::TYPE_POINTER && (node->left()->type()->name() != node->type()->name() || node->right()->type()->name() != node->type()->name())) {
    if (node->left()->type()->name() == basic_type::TYPE_INT) {
      node->left()->accept(this, lvl);
      _pf.INT(4);
      _pf.MUL();
      node->right()->accept(this, lvl);
    }
    else if (node->left()->type()->name() == basic_type::TYPE_DOUBLE) {
      node->left()->accept(this, lvl);
      _pf.D2I();
      _pf.INT(4);
      _pf.MUL();
      node->right()->accept(this, lvl);
    }
    else if (node->right()->type()->name() == basic_type::TYPE_INT) {
      node->left()->accept(this, lvl);
      node->right()->accept(this, lvl);
      _pf.INT(4);
      _pf.MUL();
    }
    else if (node->right()->type()->name() == basic_type::TYPE_DOUBLE) {
      node->left()->accept(this, lvl);
      node->right()->accept(this, lvl);
      _pf.D2I();
      _pf.INT(4);
      _pf.MUL();
    }
  }
  else {
    node->left()->accept(this, lvl);
    node->right()->accept(this, lvl);
  }
  if (node->type()->name() != basic_type::TYPE_DOUBLE)
    _pf.ADD();
  else 
    _pf.DADD();
}

void pwn::postfix_writer::do_sub_node(cdk::sub_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  if (node->type()->name() == basic_type::TYPE_DOUBLE && (node->left()->type()->name() != node->type()->name() || node->right()->type()->name() != node->type()->name())) {
    if (node->left()->type()->name() != node->type()->name()) {
      node->left()->accept(this, lvl);
      _pf.I2D();
      node->right()->accept(this, lvl);
    }
    else {
      node->left()->accept(this, lvl);
      node->right()->accept(this, lvl);
      _pf.I2D();
    }
  }
  else if (node->type()->name() == basic_type::TYPE_POINTER && (node->left()->type()->name() != node->type()->name() || node->right()->type()->name() != node->type()->name())) {
    if (node->left()->type()->name() == basic_type::TYPE_INT) {
      node->left()->accept(this, lvl);
      _pf.INT(4);
      _pf.MUL();
      node->right()->accept(this, lvl);
    }
    else if (node->left()->type()->name() == basic_type::TYPE_DOUBLE) {
      node->left()->accept(this, lvl);
      _pf.D2I();
      _pf.INT(4);
      _pf.MUL();
      node->right()->accept(this, lvl);
    }
    else if (node->right()->type()->name() == basic_type::TYPE_INT) {
      node->left()->accept(this, lvl);
      node->right()->accept(this, lvl);
      _pf.INT(4);
      _pf.MUL();
    }
    else if (node->right()->type()->name() == basic_type::TYPE_DOUBLE) {
      node->left()->accept(this, lvl);
      node->right()->accept(this, lvl);
      _pf.D2I();
      _pf.INT(4);
      _pf.MUL();
    }
  }
  else {
    node->left()->accept(this, lvl);
    node->right()->accept(this, lvl);
  }
  if (node->type()->name() != basic_type::TYPE_DOUBLE)
    _pf.SUB();
  else 
    _pf.DSUB();
}
void pwn::postfix_writer::do_mul_node(cdk::mul_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  if (node->type()->name() == basic_type::TYPE_DOUBLE && (node->left()->type()->name() != node->type()->name() || node->right()->type()->name() != node->type()->name())) {
    if (node->left()->type()->name() != node->type()->name()) {
      node->left()->accept(this, lvl);
      _pf.I2D();
    }
    else {
      node->right()->accept(this, lvl);
      _pf.I2D();
    }
  }
  else {
    node->left()->accept(this, lvl);
    node->right()->accept(this, lvl);
  }
  if (node->type()->name() != basic_type::TYPE_DOUBLE)
    _pf.MUL();
  else 
    _pf.DMUL();
}
void pwn::postfix_writer::do_div_node(cdk::div_node * const node, int lvl) {
  if (node->type()->name() == basic_type::TYPE_DOUBLE && (node->left()->type()->name() != node->type()->name() || node->right()->type()->name() != node->type()->name())) {
    if (node->left()->type()->name() != node->type()->name()) {
      node->left()->accept(this, lvl);
      _pf.I2D();
    }
    else {
      node->right()->accept(this, lvl);
      _pf.I2D();
    }
  }
  else {
    node->left()->accept(this, lvl);
    node->right()->accept(this, lvl);
  }
  if (node->type()->name() != basic_type::TYPE_DOUBLE)
    _pf.DIV();
  else 
    _pf.DDIV();
}
void pwn::postfix_writer::do_mod_node(cdk::mod_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.MOD();
}
void pwn::postfix_writer::do_lt_node(cdk::lt_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.LT();
}
void pwn::postfix_writer::do_le_node(cdk::le_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.LE();
}
void pwn::postfix_writer::do_ge_node(cdk::ge_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.GE();
}
void pwn::postfix_writer::do_gt_node(cdk::gt_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.GT();
}
void pwn::postfix_writer::do_ne_node(cdk::ne_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.NE();
}
void pwn::postfix_writer::do_eq_node(cdk::eq_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.EQ();
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_rvalue_node(pwn::rvalue_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->lvalue()->accept(this, lvl);
  if (node->type()->name() == basic_type::TYPE_INT || node->type()->name() == basic_type::TYPE_STRING || node->type()->name() == basic_type::TYPE_POINTER)
    _pf.LOAD();
  else if (node->type()->name() == basic_type::TYPE_DOUBLE)
    _pf.DLOAD();
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_lvalue_node(pwn::lvalue_node * const node, int lvl) {
  /*CHECK_TYPES(_compiler, _symtab, node);
  // simplified generation: all variables are global
  _pf.ADDR(node->value());*/
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_assignment_node(pwn::assignment_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->rvalue()->accept(this, lvl);
  if (node->lvalue()->type()->name() == basic_type::TYPE_INT || node->lvalue()->type()->name() == basic_type::TYPE_STRING || node->lvalue()->type()->name() == basic_type::TYPE_POINTER)
    _pf.DUP();
  else if (node->lvalue()->type()->name() == basic_type::TYPE_DOUBLE)
    _pf.DDUP();
  node->lvalue()->accept(this, lvl);
  if (node->lvalue()->type()->name() == basic_type::TYPE_INT || node->lvalue()->type()->name() == basic_type::TYPE_STRING || node->lvalue()->type()->name() == basic_type::TYPE_POINTER)
    _pf.STORE();
  else if (node->lvalue()->type()->name() == basic_type::TYPE_DOUBLE)
    _pf.DSTORE();
}

//---------------------------------------------------------------------------

/*void pwn::postfix_writer::do_program_node(pwn::program_node * const node, int lvl) {
  // Note that Simple doesn't have functions. Thus, it doesn't need
  // a function node. However, it must start in the main function.
  // The ProgramNode (representing the whole program) doubles as a
  // main function node.

  // generate the main function (RTS mandates that its name be "_main")
  _pf.TEXT();
  _pf.ALIGN();
  _pf.GLOBAL("_main", _pf.FUNC());
  _pf.LABEL("_main");
  _pf.ENTER(0);  // Simple doesn't implement local variables

  node->statements()->accept(this, lvl);

  // end the main function
  _pf.INT(0);
  _pf.POP();
  _pf.LEAVE();
  _pf.RET();

  // these are just a few library function imports
  _pf.EXTERN("readi");
  _pf.EXTERN("printi");
  _pf.EXTERN("prints");
  _pf.EXTERN("println");
}*/

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_evaluation_node(pwn::evaluation_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->argument()->accept(this, lvl); // determine the value
  if (node->argument()->type() != nullptr) {
    if (node->argument()->type()->name() == basic_type::TYPE_INT || node->argument()->type()->name() == basic_type::TYPE_STRING || node->argument()->type()->name() == basic_type::TYPE_POINTER) {
      _pf.TRASH(4); // delete the evaluated value
    }
    else if (node->argument()->type()->name() == basic_type::TYPE_DOUBLE) {
      _pf.TRASH(8); // delete the evaluated value's address
    }
    else {
      std::cerr << "ERROR: CANNOT HAPPEN!" << std::endl;
      exit(1);
    }
  }
}

void pwn::postfix_writer::do_print_node(pwn::print_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->argument()->accept(this, lvl); // determine the value to print
  if (node->argument()->type()->name() == basic_type::TYPE_INT) {
    _pf.CALL("printi");
    _pf.TRASH(4); // delete the printed value
  }
  else if (node->argument()->type()->name() == basic_type::TYPE_STRING) {
    _pf.CALL("prints");
    _pf.TRASH(4); // delete the printed value's address
  }
  else if (node->argument()->type()->name() == basic_type::TYPE_DOUBLE) {
    _pf.CALL("printd");
    _pf.TRASH(8); // delete the printed value's address
  }
  else {
    
    std::cerr << "ERROR: CANNOT HAPPEN!" << std::endl;
    exit(1);
  }
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_read_node(pwn::read_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  _pf.CALL("readi");
  _pf.PUSH();
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_while_node(cdk::while_node * const node, int lvl) { }

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_if_node(cdk::if_node * const node, int lvl) {
  int lbl1;
  node->condition()->accept(this, lvl);
  _pf.JZ(mklbl(lbl1 = ++_lbl));
  node->block()->accept(this, lvl + 2);
  _pf.LABEL(mklbl(lbl1));
}

//---------------------------------------------------------------------------

void pwn::postfix_writer::do_if_else_node(cdk::if_else_node * const node, int lvl) {
  int lbl1, lbl2;
  node->condition()->accept(this, lvl);
  _pf.JZ(mklbl(lbl1 = ++_lbl));
  node->thenblock()->accept(this, lvl + 2);
  _pf.JMP(mklbl(lbl2 = ++_lbl));
  _pf.LABEL(mklbl(lbl1));
  node->elseblock()->accept(this, lvl + 2);
  _pf.LABEL(mklbl(lbl1 = lbl2));
}
//---------------------------------------------------------------------------
void pwn::postfix_writer::do_identifier_node(cdk::identifier_node * const node, int lvl) { 
  
}

  //NEW NODES
void pwn::postfix_writer::do_and_node(pwn::and_node * const node, int lvl) { 
  CHECK_TYPES(_compiler, _symtab, node);
  int lbl1;
  node->left()->accept(this, lvl);
  _pf.INT(1);
  _pf.AND();
  _pf.DUP();
  _pf.JZ(mklbl(lbl1 = ++_lbl));
  node->left()->accept(this, lvl);
  node->right()->accept(this, lvl);
  _pf.AND();
  _pf.LABEL(mklbl(lbl1));
}
void pwn::postfix_writer::do_block_node(pwn::block_node * const node, int lvl) { 
  if(node->declrs() != nullptr)
    node->declrs()->accept(this, lvl);
  if(node->instrs() != nullptr)
    node->instrs()->accept(this, lvl);
}
void pwn::postfix_writer::do_function_call_node(pwn::function_call_node * const node, int lvl) { 
  CHECK_TYPES(_compiler, _symtab, node);
  const std::string &id = node->identifier();
  cdk::sequence_node* args = node->args();
  cdk::expression_node* arg;
  if (args != nullptr) {
    for(int i = args->size(); i > 0; i--) {
      args->node(i-1)->accept(this, lvl);
    }
  }
  _pf.CALL(id);
  if (args != nullptr) {
    for(size_t i = args->size(); i > 0; i--) {
      arg = (cdk::expression_node*)args->node(i-1);
      if (arg->type()->name() == basic_type::TYPE_INT || arg->type()->name() == basic_type::TYPE_POINTER || arg->type()->name() == basic_type::TYPE_STRING)
	_pf.TRASH(4);
      else if (arg->type()->name() == basic_type::TYPE_DOUBLE)
	_pf.TRASH(8);
    }
  }
  _pf.PUSH();
}
void pwn::postfix_writer::do_function_decl_node(pwn::function_decl_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  _insidefunc = true;
  _pf.TEXT();
  _pf.ALIGN();
  std::string name = node->identifier();
  int returnVar = 4;
  int size = 0;
  int argsNumber = 0;
  if (node->args() != nullptr)
    argsNumber = node->args()->size();
  if (!_symtab.find_local(name) && node->body() == nullptr) {
    cdk::sequence_node* ex = node->args();
    if (argsNumber > 0) {
      ex = nullptr;
      pwn::var_decl_node *cp;
      pwn::var_decl_node *ex2;
      int n = 4;
      for(int i = 0; i < argsNumber; i++) {
	n = 4;
	cp = (pwn::var_decl_node*)node->args()->node(i);
	if (cp->typev()->name() == basic_type::TYPE_DOUBLE)
	n=8;
	ex2 = new pwn::var_decl_node(cp->lineno(), cp->constant(), cp->local(), cp->import(), new basic_type(n, cp->typev()->name()), cp->identifier(), cp->rvalue());
	ex = new cdk::sequence_node(node->args()->lineno(), ex2, ex);
      }
    }
    _symtab.insert(name, std::make_shared<pwn::symbol>(node->typef(), name, argsNumber, ex, false, 0, true, false));
  }
  else if (!_symtab.find_local(name) && node->body() != nullptr) {
    cdk::sequence_node* ex = node->args();
    if (argsNumber > 0) {
      ex = nullptr;
      pwn::var_decl_node *cp;
      pwn::var_decl_node *ex2;
      int n = 4;
      for(int i = 0; i < argsNumber; i++) {
	n = 4;
	cp = (pwn::var_decl_node*)node->args()->node(i);
	if (cp->typev()->name() == basic_type::TYPE_DOUBLE)
	n=8;
	ex2 = new pwn::var_decl_node(cp->lineno(), cp->constant(), cp->local(), cp->import(), new basic_type(n, cp->typev()->name()), cp->identifier(), cp->rvalue());
	ex = new cdk::sequence_node(node->args()->lineno(), ex2, ex);
      }
    }
    _symtab.insert(name, std::make_shared<pwn::symbol>(node->typef(), name, argsNumber, ex, false, 0, true, true));
    _symtab.push();
    if (name == "pwn") name = "_main";
    else if (name == "_main") name = "._main";
    _offset = 8;
    _args = true;
    if(node->args() != nullptr)
      node->args()->accept(this, lvl);
    _args = false;
    if(node->typef()!= nullptr) {
      if (node->typef()->name() == basic_type::TYPE_DOUBLE)
	returnVar = 8;
    }
    else
      returnVar = 0;
    _offset = -4-returnVar;
    if (node->body() != nullptr) {
      cdk::sequence_node* declrs = node->body()->declrs();
      pwn::var_decl_node* decl;
      if (declrs != nullptr) {
	for(size_t i = 0; i < declrs->size(); i++) {
	  decl = (pwn::var_decl_node*)declrs->node(i);
	  if(decl->typev()->name() == basic_type::TYPE_INT || decl->typev()->name() == basic_type::TYPE_STRING || decl->typev()->name() == basic_type::TYPE_POINTER) 
	    size+=4;
	  else if(decl->typev()->name() == basic_type::TYPE_DOUBLE)
	    size+=8;
	}
      }
    }
    _pf.GLOBAL(name, _pf.FUNC());
    _pf.LABEL(name);
    _pf.ENTER(size + returnVar);
    if(node->lit() != nullptr)
      node->lit()->accept(this, lvl);
    else
      _pf.INT(0);
    _pf.LOCA(-4);
    if(node->body() != nullptr)
      node->body()->accept(this, lvl);
    _pf.LOCV(-4);
    _pf.POP();
    _pf.LEAVE();
    _pf.RET();
    _symtab.pop();
    // these are just a few library function imports
    if (name == "_main") {
      if (_symtab.find_local("argc"))
	_pf.EXTERN("argc");
      if (_symtab.find_local("argv"))
	_pf.EXTERN("argv");
      if (_symtab.find_local("envp"))
	_pf.EXTERN("envp");
      _pf.EXTERN("readi");
      _pf.EXTERN("printi");
      _pf.EXTERN("printd");
      _pf.EXTERN("prints");
      _pf.EXTERN("println");
    }
  }
  else {
    std::shared_ptr<pwn::symbol> symbol = _symtab.find_local(name);
    symbol->setBody(true);
    _symtab.push();
    if (name == "pwn") name = "_main";
    else if (name == "_main") name = "._main";
    _offset = 8;
    _args = true;
    if(node->args() != nullptr)
      node->args()->accept(this, lvl);
    _args = false;
    if(node->typef()!= nullptr) {
      if (node->typef()->name() == basic_type::TYPE_DOUBLE)
	returnVar = 8;
    }
    else
      returnVar = 0;
    _offset = -4-returnVar;
    if (node->body() != nullptr) {
      cdk::sequence_node* declrs = node->body()->declrs();
      pwn::var_decl_node* decl;
      if (declrs != nullptr) {
	for(size_t i = 0; i < declrs->size(); i++) {
	  decl = (pwn::var_decl_node*)declrs->node(i);
	  if(decl->typev()->name() == basic_type::TYPE_INT || decl->typev()->name() == basic_type::TYPE_STRING || decl->typev()->name() == basic_type::TYPE_POINTER) 
	    size+=4;
	  else if(decl->typev()->name() == basic_type::TYPE_DOUBLE)
	    size+=8;
	}
      }
    }
    _pf.GLOBAL(name, _pf.FUNC());
    _pf.LABEL(name);
    _pf.ENTER(size + returnVar);
    if(node->lit() != nullptr)
      node->lit()->accept(this, lvl);
    else
      _pf.INT(0);
    _pf.LOCA(-4);
    if(node->body() != nullptr)
      node->body()->accept(this, lvl);
    _pf.LOCV(-4);
    _pf.POP();
    _pf.LEAVE();
    _pf.RET();
    // these are just a few library function imports
    if (name == "_main") {
      _pf.EXTERN("readi");
      _pf.EXTERN("printi");
      _pf.EXTERN("printd");
      _pf.EXTERN("prints");
      _pf.EXTERN("println");
      /*_pf.EXTERN("argc");
      _pf.EXTERN("argv");*/
    }
    _symtab.pop();
  }
  _insidefunc = false;
  _offset = 0;
}
void pwn::postfix_writer::do_function_define_node(pwn::function_define_node * const node, int lvl) { 
    /*
   * std::string name = node->id();
   * if (name == "pwn") name = "_main";
   * else if (name == "_main") name = "._main";
   * 
   * _pf.GLOBAL(name, _pf.FUNC());
   * _pf.LABEL(name);
   * _pf.ENTER(0);
   */
}
void pwn::postfix_writer::do_identity_node(pwn::identity_node * const node, int lvl) {
  
  int lbl1;
  CHECK_TYPES(_compiler, _symtab, node);
  node->argument()->accept(this, lvl); // determine the value
  //TODO check this function
  if (node->type()->name() == basic_type::TYPE_DOUBLE) {
    _pf.DDUP();
    _pf.DOUBLE(0);
    _pf.LT();
    _pf.JZ(mklbl(lbl1 = ++_lbl));
    _pf.DNEG();
    _pf.LABEL(mklbl(lbl1));
  }
  if (node->type()->name() == basic_type::TYPE_INT) {
    _pf.DUP();
    _pf.INT(0);
    _pf.LT();
    _pf.JZ(mklbl(lbl1 = ++_lbl));
    _pf.NEG(); // 2-complement
    _pf.LABEL(mklbl(lbl1));
  }
}
void pwn::postfix_writer::do_index_node(pwn::index_node * const node, int lvl) { }
void pwn::postfix_writer::do_memory_node(pwn::memory_node * const node, int lvl) { }

void pwn::postfix_writer::do_next_node(pwn::next_node * const node, int lvl) {
  int value = node->argument()->value();
  std::string lbl1;
  int index = _stack.size() - 1 - 2 * value;
  while(value-- > 0){
    if(_stack.size() == 0)
      throw "Impossible to jump so many cycles";
    lbl1 = _stack[index];
    if(index > 1) index -= 2;
  }
  _pf.JMP(lbl1);
}

void pwn::postfix_writer::do_noob_node(pwn::noob_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  _pf.INT(0);
}

void pwn::postfix_writer::do_not_node(pwn::not_node * const node, int lvl) { 
  CHECK_TYPES(_compiler, _symtab, node);
  node->argument()->accept(this, lvl); // determine the value
  if (node->type()->name() == basic_type::TYPE_INT)
    _pf.NOT(); // 2-complement
}

void pwn::postfix_writer::do_or_node(pwn::or_node * const node, int lvl) { 
  CHECK_TYPES(_compiler, _symtab, node);
  int lbl1;
  node->left()->accept(this, lvl);
  _pf.DUP();
  _pf.JNZ(mklbl(lbl1 = ++_lbl));
//   _pf.TRASH(4);
  node->right()->accept(this, lvl);
  _pf.OR();
  _pf.LABEL(mklbl(lbl1));
}

void pwn::postfix_writer::do_println_node(pwn::println_node * const node, int lvl) { 
  CHECK_TYPES(_compiler, _symtab, node);

  node->argument()->accept(this, lvl); // determine the value to print
  if (node->argument()->type()->name() == basic_type::TYPE_INT) {
    _pf.CALL("printi");
    _pf.TRASH(4); // delete the printed value
  }
  else if (node->argument()->type()->name() == basic_type::TYPE_STRING) {
    _pf.CALL("prints");
    _pf.TRASH(4); // delete the printed value's address
  }
  else if (node->argument()->type()->name() == basic_type::TYPE_DOUBLE) {
    _pf.CALL("printd");
    _pf.TRASH(8); // delete the printed value's address
  }
  else {
    std::cerr << "ERROR: CANNOT HAPPEN!" << std::endl;
    exit(1);
  }
  _pf.CALL("println"); // print a newline
}

void pwn::postfix_writer::do_qmark_node(pwn::qmark_node * const node, int lvl) {
  CHECK_TYPES(_compiler, _symtab, node);
  node->argument()->accept(this, lvl);
}

void pwn::postfix_writer::do_repeat_node(pwn::repeat_node * const node, int lvl) {
  int condition = ++_lbl;
  int increment = ++_lbl;
  int end = ++_lbl;
  _symtab.push();
  _stack.push_back(mklbl(end));
  _stack.push_back(mklbl(increment));
  node->init()->accept(this, lvl);
  _pf.LABEL(mklbl(condition));
  node->condition()->accept(this, lvl);
  _pf.JZ(mklbl(end));
  node->block()->accept(this, lvl);
  _pf.LABEL(mklbl(increment));
  node->incr()->accept(this, lvl);
  _pf.JMP(mklbl(condition));
  _pf.LABEL(mklbl(end));
  _stack.pop_back();
  _stack.pop_back();
  _symtab.pop();
}

void pwn::postfix_writer::do_return_node(pwn::return_node * const node, int lvl) { 
  _pf.LOCV(-4);
  _pf.POP();
  _pf.LEAVE();
  _pf.RET();
}

void pwn::postfix_writer::do_stop_node(pwn::stop_node * const node, int lvl) {
  int value = node->argument()->value();
  std::string lbl1;
  int index = _stack.size() - 2 * value;
  while(value-- > 0){
    if(_stack.size() == 0)
      throw "Impossible to jump so many cycles";
    lbl1 = _stack[index];
    if(index > 1) index -= 2;
  }
  _pf.JMP(lbl1);
}

void pwn::postfix_writer::do_var_node(pwn::var_node * const node, int lvl) { 
  CHECK_TYPES(_compiler, _symtab, node);
  const std::string &id = node->identifier();
  std::shared_ptr<pwn::symbol> symbol = _symtab.find(id);
  if (!symbol->function()) {
    if(symbol->offset() == 0)
      _pf.ADDR(id);
    else
      _pf.LOCAL(symbol->offset());
  }
  else
    _pf.LOCAL(-4);
}
void pwn::postfix_writer::do_var_decl_node(pwn::var_decl_node * const node, int lvl) { 
  int lbl1, off = 0;
  CHECK_TYPES(_compiler, _symtab, node);
  if (!node->import()) {
    const std::string &id = node->identifier();
    std::shared_ptr<pwn::symbol> symbol = _symtab.find(id);
    if (!_insidefunc) {
      if (node->typev()->name() == basic_type::TYPE_INT) {
        if (node->rvalue() == nullptr) {
          _pf.BSS();
	  _pf.ALIGN();
	  _pf.BYTE(4);
	  _pf.LABEL(id);
	}
        else {
	  _pf.DATA();
          _pf.ALIGN();
          _pf.LABEL(id);
          node->rvalue()->accept(this, lvl);
        }
      }
      else if (node->typev()->name() == basic_type::TYPE_DOUBLE) {
	if (node->rvalue() == nullptr) {
          _pf.BSS();
	  _pf.ALIGN();
	  _pf.BYTE(8);
	  _pf.LABEL(id);
	}
        else {
	  node->rvalue()->accept(this, lvl);
	  _pf.DATA();
          _pf.ALIGN();
          _pf.LABEL(id);
          _pf.ID(mklbl(_lbl));
        }
      }
      else if (node->typev()->name() == basic_type::TYPE_STRING) {
        if (node->rvalue() != nullptr) {
	  _pf.RODATA();
	  _pf.ALIGN();
	  _pf.LABEL(mklbl(lbl1 = ++_lbl));
          node->rvalue()->accept(this, lvl); // determine the new value
          _pf.DATA();
          _pf.ALIGN();
          _pf.LABEL(id);
          _pf.ID(mklbl(lbl1));
        } 
        else {
          _pf.BSS();
	  _pf.ALIGN();
	  _pf.BYTE(4);
	  _pf.LABEL(id);
        }
      }
    }
    else if (!_args && _insidefunc) {
      if (node->typev()->name() == basic_type::TYPE_INT) {
        if (node->rvalue() == nullptr)
          _pf.INT(0);
        else 
          node->rvalue()->accept(this, lvl);
	_pf.LOCA(_offset);
	off=-4;
      }
      else if (node->typev()->name() == basic_type::TYPE_DOUBLE) {
	_pf.RODATA();
	_pf.ALIGN();
	_pf.LABEL(mklbl(lbl1 = ++_lbl));
	if (node->rvalue() == nullptr)
          _pf.DOUBLE(0);
        else 
          node->rvalue()->accept(this, lvl);
	_pf.TEXT();
	_pf.ALIGN();
	_pf.ADDR(mklbl(lbl1));
	_pf.DLOAD();
	_pf.LOCAL(_offset);
	_pf.DSTORE();
	off=-8;
      }
      else if (node->typev()->name() == basic_type::TYPE_STRING) {
	_pf.RODATA();
	_pf.ALIGN();
	_pf.LABEL(mklbl(lbl1 = ++_lbl));
	if (node->rvalue() == nullptr)
          _pf.STR("");
        else 
          node->rvalue()->accept(this, lvl);
	_pf.TEXT();
	_pf.ALIGN();
	_pf.ADDR(mklbl(lbl1));
	_pf.LOCA(_offset);
	off=-4;
      }
    }
    else {
      off=4;
      if (node->typev()->name() == basic_type::TYPE_DOUBLE) {
	off=8;
      }
    }
  }
  _symtab.insert(node->identifier(), std::make_shared<pwn::symbol>(node->typev(), node->identifier(), 0, nullptr, node->constant(), _offset, false, false)); // put in the symbol table
  _offset+=off;
}
// $Id: type_checker.cpp,v 1.22 2015/05/20 10:37:40 ist175551 Exp $ -*- c++ -*-
#include <string>
#include "targets/type_checker.h"
#include "ast/all.h"  // automatically generated

#define ASSERT_UNSPEC \
    { if (node->type() != nullptr && \
          node->type()->name() != basic_type::TYPE_UNSPEC) return; }

//---------------------------------------------------------------------------

void pwn::type_checker::do_integer_node(cdk::integer_node * const node, int lvl) {
  ASSERT_UNSPEC;
  node->type(new basic_type(4, basic_type::TYPE_INT));
}

void pwn::type_checker::do_double_node(cdk::double_node * const node, int lvl) { 
  ASSERT_UNSPEC;
  node->type(new basic_type(8, basic_type::TYPE_DOUBLE));
}


void pwn::type_checker::do_string_node(cdk::string_node * const node, int lvl) {
  ASSERT_UNSPEC;
  node->type(new basic_type(4, basic_type::TYPE_STRING));
}


void pwn::type_checker::do_noob_node(pwn::noob_node * const node, int lvl) {
  ASSERT_UNSPEC;
  node->type(new basic_type(4, basic_type::TYPE_POINTER));
}

//---------------------------------------------------------------------------

inline void pwn::type_checker::processUnaryExpression(cdk::unary_expression_node * const node, int lvl) {
  node->argument()->accept(this, lvl + 2);
  if (node->argument()->type()->name() != basic_type::TYPE_INT && node->argument()->type()->name() != basic_type::TYPE_DOUBLE)
    throw std::string("wrong type in argument of unary expression");

  if (node->argument()->type()->name() == basic_type::TYPE_INT)
    node->type(new basic_type(4, basic_type::TYPE_INT));
  if (node->argument()->type()->name() == basic_type::TYPE_DOUBLE)
    node->type(new basic_type(8, basic_type::TYPE_DOUBLE));
}

void pwn::type_checker::do_neg_node(cdk::neg_node * const node, int lvl) {
  processUnaryExpression(node, lvl);
}

void pwn::type_checker::do_identity_node(pwn::identity_node * const node, int lvl) {
  processUnaryExpression(node, lvl);
}

void pwn::type_checker::do_qmark_node(pwn::qmark_node * const node, int lvl) {
  node->argument()->accept(this, lvl + 2);
  // TODO: What should be checked? The variable will check itself.
  node->type(new basic_type(4, basic_type::TYPE_INT));
}

void pwn::type_checker::do_not_node(pwn::not_node * const node, int lvl) {
  processUnaryExpression(node, lvl);
}

void pwn::type_checker::do_next_node(pwn::next_node * const node, int lvl) {
  node->argument()->accept(this, lvl + 2);
  if (node->argument()->type()->name() != basic_type::TYPE_INT)
    throw std::string("wrong type in argument of next expression");
}

void pwn::type_checker::do_stop_node(pwn::stop_node * const node, int lvl) {
  node->argument()->accept(this, lvl + 2);
  if (node->argument()->type()->name() != basic_type::TYPE_INT)
    throw std::string("wrong type in argument of stop expression");
}

//---------------------------------------------------------------------------

inline void pwn::type_checker::processBinaryExpressionNoPointer(cdk::binary_expression_node * const node, int lvl) {
 ASSERT_UNSPEC;
 // Check types
 
  node->left()->accept(this, lvl + 2);
  if (node->left()->type()->name() != basic_type::TYPE_INT && node->left()->type()->name() != basic_type::TYPE_DOUBLE)
    throw std::string("wrong type in left argument of binary expression");

  node->right()->accept(this, lvl + 2);
  if (node->right()->type()->name() != basic_type::TYPE_INT && node->right()->type()->name() != basic_type::TYPE_DOUBLE)
    throw std::string("wrong type in right argument of binary expression");

  // Assign type
  if (node->left()->type()->name() == basic_type::TYPE_DOUBLE || node->right()->type()->name() == basic_type::TYPE_DOUBLE) {
    node->type(new basic_type(8, basic_type::TYPE_DOUBLE));
  }
  else {
    node->type(new basic_type(4, basic_type::TYPE_INT));
  }
}

inline void pwn::type_checker::processBinaryExpressionWithPointer(cdk::binary_expression_node * const node, int lvl) {
  ASSERT_UNSPEC;
  // Check types
  
  node->left()->accept(this, lvl + 2);
  if (node->left()->type()->name() != basic_type::TYPE_INT && node->left()->type()->name() != basic_type::TYPE_DOUBLE && node->left()->type()->name() != basic_type::TYPE_POINTER)
    throw std::string("wrong type in left argument of binary expression");

  node->right()->accept(this, lvl + 2);
  if (node->right()->type()->name() != basic_type::TYPE_INT && node->right()->type()->name() != basic_type::TYPE_DOUBLE && node->right()->type()->name() != basic_type::TYPE_POINTER)
    throw std::string("wrong type in right argument of binary expression");

  // Assign type
  if(node->left()->type()->name() == basic_type::TYPE_POINTER || node->right()->type()->name() == basic_type::TYPE_POINTER) {
    node->type(new basic_type(4, basic_type::TYPE_POINTER));
  }
  else if (node->left()->type()->name() == basic_type::TYPE_DOUBLE || node->right()->type()->name() == basic_type::TYPE_DOUBLE) {
    node->type(new basic_type(8, basic_type::TYPE_DOUBLE));
  }
  else {
    node->type(new basic_type(4, basic_type::TYPE_INT));
  }
}

void pwn::type_checker::do_add_node(cdk::add_node * const node, int lvl) {
  processBinaryExpressionWithPointer(node, lvl);
}
void pwn::type_checker::do_sub_node(cdk::sub_node * const node, int lvl) {
  processBinaryExpressionWithPointer(node, lvl);
}
void pwn::type_checker::do_mul_node(cdk::mul_node * const node, int lvl) {
  processBinaryExpressionNoPointer(node, lvl);
}
void pwn::type_checker::do_div_node(cdk::div_node * const node, int lvl) {
  processBinaryExpressionNoPointer(node, lvl);
}
void pwn::type_checker::do_mod_node(cdk::mod_node * const node, int lvl) {
  processBinaryExpressionNoPointer(node, lvl);
}
void pwn::type_checker::do_lt_node(cdk::lt_node * const node, int lvl) {
  processBinaryExpressionNoPointer(node, lvl);
}
void pwn::type_checker::do_le_node(cdk::le_node * const node, int lvl) {
  processBinaryExpressionNoPointer(node, lvl);
}
void pwn::type_checker::do_ge_node(cdk::ge_node * const node, int lvl) {
  processBinaryExpressionNoPointer(node, lvl);
}
void pwn::type_checker::do_gt_node(cdk::gt_node * const node, int lvl) {
  processBinaryExpressionNoPointer(node, lvl);
}
void pwn::type_checker::do_ne_node(cdk::ne_node * const node, int lvl) {
  processBinaryExpressionWithPointer(node, lvl);
}
void pwn::type_checker::do_eq_node(cdk::eq_node * const node, int lvl) {
  processBinaryExpressionWithPointer(node, lvl);
}

void pwn::type_checker::do_and_node(pwn::and_node * const node, int lvl) { 
  processBinaryExpressionWithPointer(node, lvl);
}

void pwn::type_checker::do_or_node(pwn::or_node * const node, int lvl) { 
  processBinaryExpressionWithPointer(node, lvl);
}
//---------------------------------------------------------------------------

void pwn::type_checker::do_rvalue_node(pwn::rvalue_node * const node, int lvl) {
  node->lvalue()->accept(this, lvl);
  node->type(node->lvalue()->type());
}

//---------------------------------------------------------------------------

void pwn::type_checker::do_lvalue_node(pwn::lvalue_node * const node, int lvl) {
}

//---------------------------------------------------------------------------

void pwn::type_checker::do_assignment_node(pwn::assignment_node * const node, int lvl) {
  ASSERT_UNSPEC;
  node->lvalue()->accept(this, lvl + 2);
  node->rvalue()->accept(this, lvl + 2);
  if(node->lvalue()->type()->name() != node->lvalue()->type()->name())
    throw std::string("wrong right parameter");
  if(node->lvalue()->type()->name() == basic_type::TYPE_INT)
    node->type(new basic_type(4, basic_type::TYPE_INT));
  else if (node->lvalue()->type()->name() == basic_type::TYPE_DOUBLE)
    node->type(new basic_type(4, basic_type::TYPE_DOUBLE));
  else if (node->lvalue()->type()->name() == basic_type::TYPE_STRING)
    node->type(new basic_type(4, basic_type::TYPE_STRING));
  else if (node->lvalue()->type()->name() == basic_type::TYPE_POINTER)
    node->type(new basic_type(4, basic_type::TYPE_POINTER));
}

//---------------------------------------------------------------------------

void pwn::type_checker::do_evaluation_node(pwn::evaluation_node * const node, int lvl) {
  node->argument()->accept(this, lvl + 2);
}

void pwn::type_checker::do_print_node(pwn::print_node * const node, int lvl) {
  node->argument()->accept(this, lvl + 2);
}

void pwn::type_checker::do_println_node(pwn::println_node * const node, int lvl) {
  node->argument()->accept(this, lvl + 2);
}

//---------------------------------------------------------------------------

void pwn::type_checker::do_read_node(pwn::read_node * const node, int lvl) {
  node->type(new basic_type(4, basic_type::TYPE_INT));
}

//---------------------------------------------------------------------------

void pwn::type_checker::do_while_node(cdk::while_node * const node, int lvl) {
}

//---------------------------------------------------------------------------

void pwn::type_checker::do_if_node(cdk::if_node * const node, int lvl) {
  node->condition()->accept(this, lvl + 4);
}

void pwn::type_checker::do_if_else_node(cdk::if_else_node * const node, int lvl) {
  node->condition()->accept(this, lvl + 4);
}

void pwn::type_checker::do_identifier_node(cdk::identifier_node * const node, int lvl) {
  ASSERT_UNSPEC;
  const std::string &id = node->value();
  std::shared_ptr<pwn::symbol> symbol = _symtab.find(id);
  if (!symbol) throw id + " undeclared";
  node->type(symbol->type());
}

//---------------------------------------------------------------------------

void pwn::type_checker::do_return_node(pwn::return_node * const node, int lvl) {
}

void pwn::type_checker::do_block_node(pwn::block_node * const node, int lvl) {
  if(node->declrs() != nullptr)
    node->declrs()->accept(this, lvl + 2);
  if(node->instrs() != nullptr)
    node->instrs()->accept(this, lvl + 2);
}

void pwn::type_checker::do_repeat_node(pwn::repeat_node * const node, int lvl) {
  node->init()->accept(this, lvl);
  node->condition()->accept(this, lvl);
  node->incr()->accept(this, lvl);
  node->block()->accept(this, lvl);
}

void pwn::type_checker::do_function_call_node(pwn::function_call_node * const node, int lvl) {
  const std::string &id = node->identifier();
  std::shared_ptr<pwn::symbol> symbol = _symtab.find(id);
  if (symbol == nullptr || !symbol->function()) throw id + " undeclared";
  cdk::sequence_node* funcArgs = symbol->args();
  size_t argsN = symbol->argsNumber();
  cdk::sequence_node* callArgs = node->args();
  cdk::expression_node* callArg;
  pwn::var_decl_node* funcArg;
  if (argsN > 0) {
    if (callArgs == nullptr || callArgs->size() != argsN)
      throw std::string("Number of arguments invalid");
  }
  else if (argsN == 0 && callArgs != nullptr)
    throw std::string("Number of arguments invalid");
  if (callArgs != nullptr) {
    for(size_t i = 0; i < callArgs->size(); i++) {
      callArg = (cdk::expression_node*) callArgs->node(i);
      callArg->accept(this, lvl + 2);
      funcArg = (pwn::var_decl_node*) funcArgs->node(i);
      if (callArg->type()->name() != funcArg->typev()->name()) {
	throw std::string("Wrong type of argument " + i);
      }
    }
  }
  if (symbol->type() != nullptr) {
    if (symbol->type()->name() == basic_type::TYPE_INT || symbol->type()->name() == basic_type::TYPE_STRING || symbol->type()->name() == basic_type::TYPE_POINTER)
      node->type(new basic_type(4, symbol->type()->name()));
    else if (symbol->type()->name() == basic_type::TYPE_DOUBLE)
      node->type(new basic_type(8, symbol->type()->name()));
  }
}

void pwn::type_checker::do_function_decl_node(pwn::function_decl_node * const node, int lvl) {
  const std::string &id = node->identifier();
  std::shared_ptr<pwn::symbol> symbol = _symtab.find_local(id);
  if (symbol && symbol->body()) throw std::string("symbol already declared");
  if (node->lit() != nullptr)
    node->lit()->accept(this, lvl + 2);
  /*if (node->typef() != nullptr && node->body() != nullptr && node->body()->instrs() != nullptr) {
    size_t last = node->body()->instrs()->size() - 1;
    node->body()->instrs()->node(last)->accept(this, lvl + 2);
    if (node->typef()->name() != node->body()->instrs()->node(last)->type()->name())
      throw std::string("return type is wrong");
  }*/
  if (node->typef() != nullptr && node->lit() != nullptr) {
    if (node->typef()->name() != node->lit()->type()->name())
      throw std::string("return type is wrong");
  }
}

void pwn::type_checker::do_function_define_node(pwn::function_define_node * const node, int lvl) {
  /*const std::string id = node->identifier();
  if (!_symtab.find(id)) {
    _symtab.insert(id, std::make_shared<pwn::symbol>(node->typef(), node->args()->size(), node->args(), node->constant())); // put in the symbol table
  }
  else 
    throw new std::string "Function already declared"*/
}

void pwn::type_checker::do_index_node(pwn::index_node * const node, int lvl) {
  if (node->var()->type()->name() != basic_type::TYPE_POINTER)
    throw std::string("wrong type in var");
  if (node->value()->type()->name() != basic_type::TYPE_INT)
    throw std::string("wrong type in value");
  
  node->var()->accept(this, lvl + 2);
  node->value()->accept(this, lvl + 2);
}

void pwn::type_checker::do_memory_node(pwn::memory_node * const node, int lvl) {
    if (node->expr()->type()->name() != basic_type::TYPE_INT)
    throw std::string("wrong type in expr");
  
  node->expr()->accept(this, lvl + 2);
}

void pwn::type_checker::do_var_node(pwn::var_node * const node, int lvl) {
  const std::string &id = node->identifier();
  std::shared_ptr<pwn::symbol> symbol = _symtab.find(id);
  if (symbol == nullptr) throw std::string(id + " undeclared");
  node->type(symbol->type());
}

void pwn::type_checker::do_var_decl_node(pwn::var_decl_node * const node, int lvl) {
  const std::string &id = node->identifier();
  if (node->rvalue() != nullptr) {
    node->rvalue()->accept(this, lvl);
    if (node->rvalue()->type()->name() != node->typev()->name())
      throw std::string("wrong type on right parameter");
  }
  if (_symtab.find_local(id)) {
    throw std::string("symbol already declared");
  }
}
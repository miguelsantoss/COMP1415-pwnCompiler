// $Id: xml_writer.cpp,v 1.18 2015/05/18 18:02:05 ist175551 Exp $ -*- c++ -*-
#include <string>
#include "targets/xml_writer.h"
#include "targets/type_checker.h"
#include "ast/all.h"  // automatically generated

//---------------------------------------------------------------------------

void pwn::xml_writer::do_sequence_node(cdk::sequence_node * const node, int lvl) {
  os() << std::string(lvl, ' ') << "<sequence_node size='" << node->size() << "'>" << std::endl;
  for (size_t i = 0; i < node->size(); i++) {
    if (node->node(i) != nullptr)
      node->node(i)->accept(this, lvl + 2);
  }
  closeTag(node, lvl);
}

//---------------------------------------------------------------------------

void pwn::xml_writer::do_integer_node(cdk::integer_node * const node, int lvl) {
  processSimple(node, lvl);
}

void pwn::xml_writer::do_double_node(cdk::double_node * const node, int lvl) {
  processSimple(node, lvl);
}

void pwn::xml_writer::do_string_node(cdk::string_node * const node, int lvl) {
  processSimple(node, lvl);
}

//---------------------------------------------------------------------------

inline void pwn::xml_writer::processUnaryExpression(cdk::unary_expression_node * const node, int lvl) {
  //CHECK_TYPES(_compiler, _symtab, node);
  openTag(node, lvl);
  node->argument()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_neg_node(cdk::neg_node * const node, int lvl) {
  processUnaryExpression(node, lvl);
}

//---------------------------------------------------------------------------

inline void pwn::xml_writer::processBinaryExpression(cdk::binary_expression_node * const node, int lvl) {
  //CHECK_TYPES(_compiler, _symtab, node);
  openTag(node, lvl);
  node->left()->accept(this, lvl + 2);
  node->right()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_add_node(cdk::add_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_sub_node(cdk::sub_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_mul_node(cdk::mul_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_div_node(cdk::div_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_mod_node(cdk::mod_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_lt_node(cdk::lt_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_le_node(cdk::le_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_ge_node(cdk::ge_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_gt_node(cdk::gt_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_ne_node(cdk::ne_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}
void pwn::xml_writer::do_eq_node(cdk::eq_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}

//---------------------------------------------------------------------------

void pwn::xml_writer::do_rvalue_node(pwn::rvalue_node * const node, int lvl) {
  //CHECK_TYPES(_compiler, _symtab, node);
  openTag(node, lvl);
  if (node->lvalue() != nullptr)
    node->lvalue()->accept(this, lvl + 4);
  closeTag(node, lvl);
}

//---------------------------------------------------------------------------

void pwn::xml_writer::do_lvalue_node(pwn::lvalue_node * const node, int lvl) {
  /*CHECK_TYPES(_compiler, _symtab, node);
  processSimple(node, lvl);*/
}

//---------------------------------------------------------------------------

void pwn::xml_writer::do_assignment_node(pwn::assignment_node * const node, int lvl) {
  //CHECK_TYPES(_compiler, _symtab, node);
  openTag(node, lvl);
  node->lvalue()->accept(this, lvl + 2);
  openTag("rvalue", lvl + 2);
  node->rvalue()->accept(this, lvl + 4);
  closeTag("rvalue", lvl + 2);
  closeTag(node, lvl);
}

//---------------------------------------------------------------------------

/*void pwn::xml_writer::do_program_node(pwn::program_node * const node, int lvl) {
  openTag(node, lvl);
  node->statements()->accept(this, lvl + 4);
  closeTag(node, lvl);
}*/

//---------------------------------------------------------------------------

void pwn::xml_writer::do_evaluation_node(pwn::evaluation_node * const node, int lvl) {
  //CHECK_TYPES(_compiler, _symtab, node);
  openTag(node, lvl);
  node->argument()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_print_node(pwn::print_node * const node, int lvl) {
  //CHECK_TYPES(_compiler, _symtab, node);
  openTag(node, lvl);
  node->argument()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

//---------------------------------------------------------------------------

void pwn::xml_writer::do_read_node(pwn::read_node * const node, int lvl) {
  openTag(node, lvl);
  closeTag(node, lvl);
}

//---------------------------------------------------------------------------

void pwn::xml_writer::do_while_node(cdk::while_node * const node, int lvl) {
  /*openTag(node, lvl);
  openTag("condition", lvl + 2);
  node->condition()->accept(this, lvl + 4);
  closeTag("condition", lvl + 2);
  openTag("block", lvl + 2);
  node->block()->accept(this, lvl + 4);
  closeTag("block", lvl + 2);
  closeTag(node, lvl);*/
}

//---------------------------------------------------------------------------

void pwn::xml_writer::do_if_node(cdk::if_node * const node, int lvl) {
  openTag(node, lvl);
  openTag("condition", lvl + 2);
  node->condition()->accept(this, lvl + 4);
  closeTag("condition", lvl + 2);
  openTag("then", lvl + 2);
  node->block()->accept(this, lvl + 4);
  closeTag("then", lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_if_else_node(cdk::if_else_node * const node, int lvl) {
  openTag(node, lvl);
  openTag("condition", lvl + 2);
  node->condition()->accept(this, lvl + 4);
  closeTag("condition", lvl + 2);
  openTag("then", lvl + 2);
  node->thenblock()->accept(this, lvl + 4);
  closeTag("then", lvl + 2);
  openTag("else", lvl + 2);
  node->elseblock()->accept(this, lvl + 4);
  closeTag("else", lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_identifier_node(cdk::identifier_node * const node, int lvl) { }

//---------------------------------------------------------------------------

  //NEW NODES
void pwn::xml_writer::do_and_node(pwn::and_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}

void pwn::xml_writer::do_or_node(pwn::or_node * const node, int lvl) {
  processBinaryExpression(node, lvl);
}

void pwn::xml_writer::do_not_node(pwn::not_node * const node, int lvl) {
  processUnaryExpression(node, lvl);
}

void pwn::xml_writer::do_println_node(pwn::println_node * const node, int lvl) {
  //CHECK_TYPES(_compiler, _symtab, node);
  openTag(node, lvl);
  node->argument()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_block_node(pwn::block_node * const node, int lvl) {
  openTag(node, lvl);
  if(node->declrs() != nullptr)
    node->declrs()->accept(this, lvl + 2);
  if(node->instrs() != nullptr)
    node->instrs()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_function_call_node(pwn::function_call_node * const node, int lvl) {
  openTag(node, lvl);
  os() << std::string(lvl + 2, ' ') << "identifier: " << node->identifier() << std::endl;
  if (node->args() != nullptr) 
    node->args()->accept(this, lvl + 2);
  else 
    os() << std::string(lvl + 2, ' ') << "No args" << node->identifier() << std::endl;
  closeTag(node, lvl);
}

void pwn::xml_writer::do_function_decl_node(pwn::function_decl_node * const node, int lvl) {
  std::string scope;
  if (node->local()) {
    scope = "scope: local";
  }
  else if(node->import()) {
    scope = "scope: import";
  }
  openTag(node, lvl);
  os() << std::string(lvl + 2, ' ') << "identifier: " << node->identifier() << " " << scope << std::endl;
  if (node->lit() != nullptr)
    node->lit()->accept(this, lvl + 2);
  if (node->body() != nullptr)
    node->body()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_function_define_node(pwn::function_define_node * const node, int lvl) {
}

void pwn::xml_writer::do_identity_node(pwn::identity_node * const node, int lvl) {
  processUnaryExpression(node, lvl);
}

void pwn::xml_writer::do_index_node(pwn::index_node * const node, int lvl) {
  openTag(node, lvl);
  node->var()->accept(this, lvl + 2);
  node->value()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_memory_node(pwn::memory_node * const node, int lvl) {
  openTag(node, lvl);
  node->expr()->accept(this, lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_next_node(pwn::next_node * const node, int lvl) {
  openTag(node, lvl);
  os() << std::string(lvl + 2, ' ') << "Arg is";
  node->argument()->accept(this, lvl + 2);
  os() << std::endl;
  closeTag(node, lvl);
}

void pwn::xml_writer::do_noob_node(pwn::noob_node * const node, int lvl) {
  openTag(node, lvl);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_qmark_node(pwn::qmark_node * const node, int lvl) {
  processUnaryExpression(node, lvl);
}

void pwn::xml_writer::do_repeat_node(pwn::repeat_node * const node, int lvl) {
  openTag(node, lvl);
  if (node->init() != nullptr) {
    openTag("initialization", lvl + 2);
    node->init()->accept(this, lvl + 4);
    closeTag("initialization", lvl + 2);
  }
  if (node->condition() != nullptr) {
    openTag("condition", lvl + 2);
    node->condition()->accept(this, lvl + 4);
    closeTag("condition", lvl + 2);
  }
  
  if (node->incr() != nullptr) {
    openTag("increment", lvl + 2);
    node->incr()->accept(this, lvl + 4);
    closeTag("increment", lvl + 2);
  }
  openTag("block", lvl + 2);
  node->block()->accept(this, lvl + 4);
  closeTag("block", lvl + 2);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_return_node(pwn::return_node * const node, int lvl) {
  openTag(node, lvl);
  closeTag(node, lvl);
}

void pwn::xml_writer::do_stop_node(pwn::stop_node * const node, int lvl) {
  openTag(node, lvl);
  os() << std::string(lvl + 2, ' ') << "Arg is";
  node->argument()->accept(this, lvl + 2);
  os() << std::endl;
  closeTag(node, lvl);
}

void pwn::xml_writer::do_var_node(pwn::var_node * const node, int lvl) {
  openTag(node, lvl);
  os() << std::string(lvl + 2, ' ') << "Var name is " << node->identifier() << std::endl;
  closeTag(node, lvl);
}

void pwn::xml_writer::do_var_decl_node(pwn::var_decl_node * const node, int lvl) {
  std::string scope;
  if (node->local()) {
    scope = "scope: local";
  }
  else if(node->import()) {
    scope = "scope: import";
  }
  openTag(node, lvl);
  os() << std::string(lvl + 2, ' ') << "identifier: " << node->identifier() << " " << scope << std::endl;
  if (node->rvalue() != nullptr)
    node->rvalue()->accept(this, lvl + 2);
  closeTag(node, lvl);
}
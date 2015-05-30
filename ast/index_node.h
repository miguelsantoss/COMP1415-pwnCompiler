#ifndef __PWN_INDEX_NODE_H__
#define __PWN_INDEX_NODE_H__

#include <cdk/ast/expression_node.h>
#include "ast/lvalue_node.h"

namespace pwn {

  /**
   * Class for describing index nodes.
   */
  class index_node: public pwn::lvalue_node {
    cdk::expression_node *_var;
    cdk::expression_node *_value;
  public:
    inline index_node(int lineno, cdk::expression_node *var, cdk::expression_node *value) :
        pwn::lvalue_node(lineno), _var(var), _value(value) {
    }

  public:
    inline cdk::expression_node *var() {
      return _var;
    }
    inline cdk::expression_node *value() {
      return _value;
    }
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_index_node(this, level);
    }

  };

} // pwn

#endif

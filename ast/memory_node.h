#ifndef __PWN_MEMORY_NODE_H__
#define __PWN_MEMORY_NODE_H__

#include "ast/lvalue_node.h"
#include <cdk/ast/expression_node.h>
#include <cdk/ast/unary_expression_node.h>

namespace pwn {

  /**
   * Class for describing memory nodes.
   */
  class memory_node: public cdk::unary_expression_node {
    cdk::expression_node *_expr;
    
  public:
    inline memory_node(int lineno, cdk::expression_node *expr) :
        cdk::unary_expression_node(lineno, expr){ }

  public:
    inline cdk::expression_node *expr() {
      return _expr;
    }

    void accept(basic_ast_visitor *sp, int level) {
      sp->do_memory_node(this, level);
    }

  };

} // pwn

#endif

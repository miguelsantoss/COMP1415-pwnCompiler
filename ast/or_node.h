#ifndef __PWN_OR_NODE_H__
#define __PWN_OR_NODE_H__

#include <cdk/ast/expression_node.h>
#include <cdk/ast/binary_expression_node.h>

namespace pwn {

  /**
   * Class for describing or nodes.
   */
  class or_node : public cdk::binary_expression_node {

  public:
    inline or_node(int lineno, cdk::expression_node *leftCondition, cdk::expression_node *rightCondition) :
        binary_expression_node(lineno, leftCondition, rightCondition) {
    }

    void accept(basic_ast_visitor *sp, int level) {
      sp->do_or_node(this, level);
    }

  };

} // pwn

#endif
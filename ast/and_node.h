#ifndef __PWN_AND_NODE_H__
#define __PWN_AND_NODE_H__

#include <cdk/ast/expression_node.h>
#include <cdk/ast/binary_expression_node.h>

namespace pwn {

  /**
   * Class for describing and nodes.
   */
  class and_node : public cdk::binary_expression_node {

  public:
    inline and_node(int lineno, cdk::expression_node *leftCondition, cdk::expression_node *rightCondition) :
        cdk::binary_expression_node(lineno, leftCondition, rightCondition) {
    }

    void accept(basic_ast_visitor *sp, int level) {
      sp->do_and_node(this, level);
    }

  };

} // pwn

#endif
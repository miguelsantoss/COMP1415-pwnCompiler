#ifndef __PWN_NOT_NODE_H__
#define __PWN_NOT_NODE_H__

#include <cdk/ast/unary_expression_node.h>
#include <cdk/ast/expression_node.h>

namespace pwn {

  /**
   * Class for describing the not identifier
   */
  class not_node: public cdk::unary_expression_node {
  public:
    inline not_node(int lineno, cdk::expression_node *arg) :
        cdk::unary_expression_node(lineno, arg) {
    }

    /**
     * @param sp semantic processor visitor
     * @param level syntactic tree level
     */
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_not_node(this, level);
    }

  };

} // pwn

#endif

// $Id: lvalue_node.h,v 1.2 2015/04/11 19:24:24 ist175541 Exp $
#ifndef __PWN_NODE_EXPRESSION_LEFTVALUE_H__
#define __PWN_NODE_EXPRESSION_LEFTVALUE_H__

#include "ast/lvalue_node.h"
#include <cdk/ast/expression_node.h>
#include <string>

namespace pwn {

  /**
   * Class for describing syntactic tree leaves for holding lvalues.
   */
  class lvalue_node: public cdk::expression_node {
  public:
    inline lvalue_node(int lineno) : cdk::expression_node(lineno) {}

    /**
     * @param sp semantic processor visitor
     * @param level syntactic tree level
     */
    virtual void accept(basic_ast_visitor *sp, int level) {
      sp->do_lvalue_node(this, level);
    }

  };

} // pwn

#endif

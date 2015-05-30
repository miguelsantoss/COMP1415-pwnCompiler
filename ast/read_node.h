// $Id: read_node.h,v 1.5 2015/04/13 21:42:43 ist175551 Exp $ -*- c++ -*-
#ifndef __PWN_READ_NODE_H__
#define __PWN_READ_NODE_H__

#include <cdk/ast/expression_node.h>

namespace pwn {

  /**
   * Class for describing read nodes.
   */
  class read_node: public cdk::expression_node {
  public:
    inline read_node(int lineno) :
        cdk::expression_node(lineno) {
    }

  public:
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_read_node(this, level);
    }

  };

} // pwn

#endif

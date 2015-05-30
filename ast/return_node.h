#ifndef __PWN_RETURN_NODE_H__
#define __PWN_RETURN_NODE_H__

#include <cdk/ast/basic_node.h>
#include <cdk/ast/expression_node.h>

namespace pwn {

  /**
   * Class for describing return nodes.
   */
  class return_node: public cdk::basic_node {
  public:
    inline return_node(int lineno) :
        cdk::basic_node(lineno) {
    }

  public:
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_return_node(this, level);
    }

  };

} // pwn

#endif

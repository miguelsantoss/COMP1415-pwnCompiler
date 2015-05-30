#ifndef __PWN_PRINTLN_NODE_H__
#define __PWN_PRINTLN_NODE_H__

#include <cdk/ast/expression_node.h>

namespace pwn {

  /**
   * Class for describing println nodes.
   */
  class println_node: public cdk::basic_node {
    cdk::expression_node *_argument;

  public:
    inline println_node(int lineno, cdk::expression_node *argument) :
        cdk::basic_node(lineno), _argument(argument) {
    }

  public:
    inline cdk::expression_node *argument() {
      return _argument;
    }

    void accept(basic_ast_visitor *sp, int level) {
      sp->do_println_node(this, level);
    }

  };

} // pwn

#endif
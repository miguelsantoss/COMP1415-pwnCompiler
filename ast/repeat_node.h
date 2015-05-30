#ifndef __PWN_REPEAT_NODE_H__
#define __PWN_REPEAT_NODE_H__

#include <cdk/ast/sequence_node.h>
#include <cdk/ast/basic_node.h>
#include "ast/block_node.h"

namespace pwn {

  /**
   * Class for describing repeat-cycle nodes.
   */
  class repeat_node: public cdk::basic_node {
    cdk::sequence_node *_init;
    cdk::sequence_node *_condition;
    cdk::sequence_node *_incr;
    cdk::basic_node *_block;

  public:
    inline repeat_node(int lineno, cdk::sequence_node *init, cdk::sequence_node *condition, cdk::sequence_node *incr, cdk::basic_node *block) :
        cdk::basic_node(lineno), _init(init), _condition(condition), _incr(incr), _block(block) { }

  public:
    inline cdk::sequence_node *init() {
      return _init;
    }
    inline cdk::sequence_node *condition() {
      return _condition;
    }
    inline cdk::sequence_node *incr() {
      return _incr;
    }
    inline cdk::basic_node *block() {
      return _block;
    }

    void accept(basic_ast_visitor *sp, int level) {
      sp->do_repeat_node(this, level);
    }

  };

} // pwn

#endif

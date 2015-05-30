// $Id: block_node.h,v 1.4 2015/05/18 18:02:05 ist175551 Exp $ -*- c++ -*-
#ifndef __PWN_BLOCK_NODE_H__
#define __PWN_BLOCK_NODE_H__

#include <cdk/ast/sequence_node.h>

namespace pwn {

  /**
   * Class for describing block nodes.
   */
  class block_node: public cdk::basic_node {
    cdk::sequence_node *_declrs;
    cdk::sequence_node *_instrs;

  public:
    inline block_node(int lineno, cdk::sequence_node *declrs, cdk::sequence_node *instrs) :
        cdk::basic_node(lineno), _declrs(declrs), _instrs(instrs) {
    }

  public:
    inline cdk::sequence_node *declrs() {
      return _declrs;
    }
    inline cdk::sequence_node *instrs() {
      return _instrs;
    }
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_block_node(this, level);
    }

  };

} // pwn

#endif

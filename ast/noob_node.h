#ifndef __PWN_NOOB_NODE_H__
#define __PWN_NOOB_NODE_H__

#include <cdk/ast/expression_node.h>

namespace pwn {

  /**
   * Class for describing the noob identifier
   */
  class noob_node: public cdk::expression_node {
  public:
    inline noob_node(int lineno) :
        cdk::expression_node(lineno) {
    }

    /**
     * @param sp semantic processor visitor
     * @param level syntactic tree level
     */
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_noob_node(this, level);
    }

  };

} // pwn

#endif

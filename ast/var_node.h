#ifndef __PWN_VAR_NODE_H__
#define __PWN_VAR_NODE_H__

#include <string>
#include <cdk/ast/expression_node.h>
#include "ast/lvalue_node.h"

namespace pwn {

  /**
   * Class for describing the var class
   */
  class var_node: public lvalue_node {
    std::string _identifier;
  public:
    inline var_node(int lineno, const std::string &identifier) : pwn::lvalue_node(lineno) { _identifier = identifier; }
    
    inline const std::string identifier() const {
      return _identifier;
    }

    /**
     * @param sp semantic processor visitor
     * @param level syntactic tree level
     */
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_var_node(this, level);
    }

  };

} // pwn

#endif

#ifndef __PWN_FUNCTION_CALL_NODE_H__
#define __PWN_FUNCTION_CALL_NODE_H__

#include <cdk/ast/expression_node.h>
#include <cdk/ast/sequence_node.h>
#include <string>

namespace pwn {

  /**
   * Class for describing the function_call class
   */
  class function_call_node: public cdk::expression_node {
    std::string _identifier; 
    cdk::sequence_node *_args;
  public:
    inline function_call_node(int lineno, const std::string &identifier, cdk::sequence_node *args) :
       cdk::expression_node(lineno), _identifier(identifier), _args(args) {
    }
    inline const std::string identifier() const {
      return _identifier;
    }
    inline cdk::sequence_node *args() {
      return _args;
    }

    /**
     * @param sp semantic processor visitor
     * @param level syntactic tree level
     */
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_function_call_node(this, level);
    }

  };

} // pwn

#endif

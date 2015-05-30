#ifndef __PWN_FUNCTION_DEFINE_NODE_H__
#define __PWN_FUNCTION_DEFINE_NODE_H__

#include <cdk/ast/sequence_node.h>
#include <string>


namespace pwn {

  /**
   * Class for describing function_define nodes.
   */
  class function_define_node: public cdk::basic_node {
    cdk::expression_node *_type;
    std::string _identifier;
    cdk::sequence_node *_body;

  public:
    inline function_define_node(int lineno, cdk::expression_node *type, const std::string &identifier, cdk::sequence_node *body) :
        cdk::basic_node(lineno), _type(type), _identifier(identifier), _body(body) {
    }

  public:

    inline cdk::expression_node *type() {
      return _type;
    }

    inline cdk::sequence_node *body() {
      return _body;
    }

    inline std::string identifier() const {
      return _identifier;
    }

    void accept(basic_ast_visitor *sp, int level) {
      sp->do_function_define_node(this, level);
    }

  };

} // pwn

#endif
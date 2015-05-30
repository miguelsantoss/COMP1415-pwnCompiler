#ifndef __PWN_FUNCTION_DECL_NODE_H__
#define __PWN_FUNCTION_DECL_NODE_H__

#include <cdk/basic_type.h>
#include <cdk/ast/sequence_node.h>
#include <cdk/ast/expression_node.h>
#include <string>

namespace pwn {

  /**
   * Class for describing the function_decl class
   */
  class function_decl_node: public cdk::basic_node {
    std::string _identifier;
    bool _local;
    bool _import;
    basic_type *_typef;
    cdk::sequence_node *_args;
    pwn::block_node *_body;
    cdk::expression_node *_lit;
  public:
    inline function_decl_node(int lineno, bool local, bool import, basic_type *typef, const std::string &identifier,  
			       cdk::sequence_node *args, cdk::expression_node *lit, pwn::block_node *body) :
       cdk::basic_node(lineno), _identifier(identifier), _typef(typef), _args(args), _body(body), _lit(lit) {
      _local = local;
      _import = import;
    }
    inline const std::string identifier() const {
      return _identifier;
    }
    inline basic_type *typef() {
      return _typef;
    }
    inline bool local() {
      return _local;
    }
    inline bool import() {
      return _import;
    }
    inline cdk::sequence_node *args() {
      return _args;
    }
    inline cdk::expression_node *lit() {
      return _lit;
    }
    inline pwn::block_node *body() {
      return _body;
    }
    /**
     * @param sp semantic processor visitor
     * @param level syntactic tree level
     */
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_function_decl_node(this, level);
    }

  };

} // pwn

#endif

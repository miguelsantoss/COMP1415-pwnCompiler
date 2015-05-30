#ifndef __PWN_VAR_DECL_NODE_H__
#define __PWN_VAR_DECL_NODE_H__

#include <string>
#include <cdk/basic_type.h>
#include <cdk/ast/expression_node.h>
#include <cdk/ast/basic_node.h>
#include "ast/lvalue_node.h"

namespace pwn {

  /**
   * Class for describing the var class
   */
  class var_decl_node: public cdk::basic_node {
    std::string _identifier;
    bool _constant;
    bool _local;
    bool _import;
    basic_type *_typev;
    cdk::expression_node *_rvalue;
  public:
    inline var_decl_node(int lineno, bool constant, bool local, bool import, basic_type *typev, const std::string &identifier, cdk::expression_node *rvalue) :
       cdk::basic_node(lineno), _identifier(identifier), _typev(typev), _rvalue(rvalue) {
      _constant = constant;
      _local = local;
      _import = import;
    }
    
    inline const std::string identifier() const {
      return _identifier;
    }
    inline basic_type *typev() {
      return _typev;
    }
    inline bool constant() {
      return _constant;
    }
    inline bool local() {
      return _local;
    }
    inline bool import() {
      return _import;
    }
    inline cdk::expression_node *rvalue() {
      return _rvalue;
    }
    
    /**
     * @param sp semantic processor visitor
     * @param level syntactic tree level
     */
    void accept(basic_ast_visitor *sp, int level) {
      sp->do_var_decl_node(this, level);
    }

  };

} // pwn

#endif

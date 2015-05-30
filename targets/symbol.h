// $Id: symbol.h,v 1.6 2015/05/20 00:31:14 ist175551 Exp $ -*- c++ -*-
#ifndef __PWN_SEMANTICS_SYMBOL_H__
#define __PWN_SEMANTICS_SYMBOL_H__

#include <string>
#include <cdk/basic_type.h>
#include <cdk/ast/sequence_node.h>

namespace pwn {

    class symbol {
      basic_type *_type;
      std::string _name;
      int _argsNumber;
      cdk::sequence_node *_args;
      bool _constant;
      int _offset;
      bool _function;
      bool _body;

    public:
      inline symbol(basic_type *type, const std::string &name, int argsNumber, cdk::sequence_node *args, bool constant, int offset, bool function, bool body) :
          _type(type), _name(name), _args(args) {
	    _argsNumber = argsNumber;
	    _constant = constant;
	    _offset = offset;
	    _function = function;
	    _body = body;
      }

      virtual ~symbol() {
        delete _type;
      }

      inline basic_type *type() const {
        return _type;
      }
      inline const std::string &name() const {
        return _name;
      }
      inline const int argsNumber() const {
	return _argsNumber;
      }
      inline cdk::sequence_node *args() const {
        return _args;
      }
      inline const bool constant() const {
	return _constant;
      }
      inline const int offset() const {
	return _offset;
      }
      inline const bool function() const {
	return _function;
      }
      inline const bool body() const {
	return _body;
      }
      inline void setBody(bool s) {
	_body = s;
      }
    };

} // pwn

#endif

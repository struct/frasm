#include <ruby.h>
#include "decoder.h"
#include "textdefs.h"
#include "wstring.h"

#define MAX_INSTRUCTIONS 1000

static VALUE rb_mDistorm;
static VALUE rb_cDistorm;
static VALUE rb_cInsn;

static VALUE _decode(int argc, VALUE *argv, VALUE self)
{
  VALUE ret = Qnil;
  _DecodeType dect = Decode32Bits;
  uint8_t *str = NULL;
  size_t len = 0;
  VALUE buf = Qnil;
  VALUE opts = Qnil;
  ID newv = rb_intern("new");
	
  if(!argc) { 
	rb_raise(rb_eTypeError, "wrong/insufficient arguments (expect String, opts");
  } else {
	_DecodeResult e = DECRES_NONE;
	_DecodedInst insns[MAX_INSTRUCTIONS];
	unsigned int icnt = 0;
	_OffsetType off = 0;
	buf = argv[0];

	Check_Type(buf, T_STRING);

	if(argc > 1) { 
	  VALUE o = Qnil;
	  Check_Type(argv[1], T_HASH);
	  opts = argv[1];
	  
	  if((o = rb_hash_aref(opts, rb_intern("decode_type"))) != Qnil) {
		Check_Type(o, T_FIXNUM);
		switch((int)o) {
		case 16:
		  dect = Decode16Bits;
		  break;
		case 32:
		  dect = Decode32Bits;
		  break;
		case 64:
		  dect = Decode64Bits;
		  break;
		default:
		  rb_raise(rb_eTypeError, "bad value for decode_type");
		  return(ret);
		}
	  }
	}

	ret = rb_ary_new();
	str = (uint8_t *) RSTRING_PTR(buf);
	len = RSTRING_LEN(buf);

	while(e != DECRES_SUCCESS) { 
	  VALUE insn = Qnil;
	  u_char text[MAX_TEXT_SIZE*2];
	  int i = 0;
	  e = distorm_decode(off, str, len, dect, insns, MAX_INSTRUCTIONS, &icnt);

	  if((e == DECRES_MEMORYERR) && (icnt == 0))
		break;

	  for(i = 0; i < icnt; i++) { 
		if(insns[i].mnemonic.length > 0) { 
		  memcpy(text, insns[i].mnemonic.p, insns[i].mnemonic.length + 1);
		  if(insns[i].operands.length > 0) 
			text[insns[i].mnemonic.length] = SP_CHR;
		  memcpy(&text[insns[i].mnemonic.length+1], insns[i].operands.p, insns[i].operands.length+ 1);
		  text[insns[i].mnemonic.length+1+insns[i].operands.length+1] = 0;
		} else
		  text[0] = 0;

		insn = rb_funcall(rb_cInsn, newv, 0);
		rb_iv_set(insn, "@mnem", rb_str_new2((char *)text));
		rb_iv_set(insn, "@offset", INT2NUM(insns[i].offset));
		rb_iv_set(insn, "@size", INT2NUM(insns[i].size));
		rb_iv_set(insn, "@raw", rb_str_new2((char *)insns[i].instructionHex.p));
		rb_ary_push(ret, insn);
	  }	 
	}
  }
 
  return(ret);
}

void
Init_frasm() {
  rb_mDistorm = rb_define_module("Frasm");
  rb_cDistorm = rb_define_class_under(rb_mDistorm, "DistormDecoder", rb_cObject); 
  rb_cInsn = rb_define_class_under(rb_mDistorm, "Insn", rb_cObject);
  rb_define_attr(rb_cInsn, "offset", 1, 1);
  rb_define_attr(rb_cInsn, "mnem", 1, 1);
  rb_define_attr(rb_cInsn, "size", 1, 1);
  rb_define_attr(rb_cInsn, "raw", 1, 1);

  rb_define_method(rb_cDistorm, "decode", _decode, -1);
}

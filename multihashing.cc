#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "neoscrypt.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "s3.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "x14.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "dcrypt.h"
    #include "jh.h"
    #include "x5.h"
    #include "c11.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;

Handle<Value> except(const char* msg) {
    return v8::Isolate::GetCurrent()->ThrowException(Exception::Error(String::NewFromUtf8(v8::Isolate::GetCurrent(), msg)));
}

void quark(const FunctionCallbackInfo<v8::Value> &args) {
	  Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 1) {
        args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
			}

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target)) {
        args.GetReturnValue().Set( except("Argument should be a buffer object.") );
				return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
    args.GetReturnValue().Set(  buff );
}

void x11(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
			}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
				args.GetReturnValue().Set( except("Argument should be a buffer object.") );
				return;
		}


    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
    args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void x5(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
			}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
				args.GetReturnValue().Set( except("Argument should be a buffer object.") );
				return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
    args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void scrypt(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);


   if (args.Length() < 3) {
       args.GetReturnValue().Set( except("You must provide buffer to hash, N value, and R value") );
			 return;
	}

   Local<Object> target = args[0]->ToObject();

	 if(!Buffer::HasInstance(target)) {
			 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
			 return;
	 }

   Local<Number> numn = args[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = args[2]->ToNumber();
   unsigned int rValue = numr->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

	 Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
	 args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void neoscrypt_hash(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 2) {
        args.GetReturnValue().Set(  except("You must provide two arguments.") );
				return;
		}

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
 			 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
 			 return;
 	 }

    char * input = Buffer::Data(target);
    char output[32];

    //uint32_t input_len = Buffer::Length(target);

    neoscrypt(input, output, 0);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
 	  args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}


void scryptn(const FunctionCallbackInfo<v8::Value> &args) {
	 Isolate *isolate = v8::Isolate::GetCurrent();
	 v8::EscapableHandleScope handle_scope(isolate);

   if (args.Length() < 2) {
       args.GetReturnValue().Set( except("You must provide buffer to hash and N factor.") );
			 return;
	 }

   Local<Object> target = args[0]->ToObject();

	 if(!Buffer::HasInstance(target)) {
			args.GetReturnValue().Set( except("Argument should be a buffer object.") );
			return;
	 }

   Local<Number> num = args[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


	 Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
	 args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void scryptjane(const FunctionCallbackInfo<v8::Value> &args) {
	  Isolate *isolate = v8::Isolate::GetCurrent();
    v8::EscapableHandleScope handle_scope(isolate);


    if (args.Length() < 5) {
        args.GetReturnValue().Set( except("You must provide five argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax") );
				return;
		}

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
 			args.GetReturnValue().Set( except("Argument should be a buffer object.") );
 			return;
 	 }

    Local<Number> num = args[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = args[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = args[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = args[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
 	  args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void yescrypt(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);


    if (args.Length() < 1) {
        args.GetReturnValue().Set(  except("You must provide one argument.") );
				return;
		}

   Local<Object> target = args[0]->ToObject();

	 if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
	}

   char * input = Buffer::Data(target);
   char output[32];

   yescrypt_hash(input, output);

	 Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
 	 args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void keccak(const FunctionCallbackInfo<v8::Value> &args) {
	  Isolate *isolate = v8::Isolate::GetCurrent();
	  v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 1) {
        args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
	  }

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
 		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
 		 return;
 	}


    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}


void bcrypt(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
	  v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 1) {
        args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
	  }

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
 		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
 		 return;
 	  }

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void skein(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	if (args.Length() < 1) {
			args.GetReturnValue().Set( except("You must provide one argument.") );
			return;
	}

	Local<Object> target = args[0]->ToObject();

	if(!Buffer::HasInstance(target)) {
	 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
	 return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}


void groestl(const FunctionCallbackInfo<v8::Value> &args) {
	  Isolate *isolate = v8::Isolate::GetCurrent();
	  v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}


void groestlmyriad(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	if (args.Length() < 1) {
			args.GetReturnValue().Set( except("You must provide one argument.") );
			return;
	}

	Local<Object> target = args[0]->ToObject();

	if(!Buffer::HasInstance(target)) {
	 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
	 return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}


void blake(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void dcrypt(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}
    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    dcrypt_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void fugue(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}


void qubit(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}


    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void s3(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	if (args.Length() < 1) {
			args.GetReturnValue().Set( except("You must provide one argument.") );
			return;
	}

	Local<Object> target = args[0]->ToObject();

	if(!Buffer::HasInstance(target)) {
	 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
	 return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    s3_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void hefty1(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	if (args.Length() < 1) {
			args.GetReturnValue().Set( except("You must provide one argument.") );
			return;
	}

	Local<Object> target = args[0]->ToObject();

	if(!Buffer::HasInstance(target)) {
	 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
	 return;
	}


    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
  	args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}


void shavite3(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	if (args.Length() < 1) {
			args.GetReturnValue().Set( except("You must provide one argument.") );
			return;
	}

	Local<Object> target = args[0]->ToObject();

	if(!Buffer::HasInstance(target)) {
	 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
	 return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void cryptonight(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

    bool fast = false;

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

    if (args.Length() >= 2) {
        if(!args[1]->IsBoolean()) {
					  args.GetReturnValue().Set( except("Argument 2 should be a boolean") );
						return;
				}
        fast = args[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void x13(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}


    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void x14(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
				args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

		Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x14_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void boolberry(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 2) {
        	args.GetReturnValue().Set(  except("You must provide two arguments.") );
					return;
		}

    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target)) {
        	args.GetReturnValue().Set(  except("Argument 1 should be a buffer object.") );
					return;
		}

    if(!Buffer::HasInstance(target_spad)) {
        	args.GetReturnValue().Set(  except("Argument 2 should be a buffer object.") );
					return;
		}

    if(args.Length() >= 3) {
        if(args[2]->IsUint32()) {
            height = args[2]->ToUint32()->Uint32Value();
				} else {
            	args.GetReturnValue().Set( except("Argument 3 should be an unsigned integer.") );
							return;
			  }
		}

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void nist5(const FunctionCallbackInfo<v8::Value> &args) {
		Isolate *isolate = v8::Isolate::GetCurrent();
		v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 1) {
        args.GetReturnValue().Set( except("You must provide one argument.") );
				return;
		}

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void sha1(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 1) {
        args.GetReturnValue().Set(  except("You must provide one argument.") );
				return;
		}

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void x15(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

    if (args.Length() < 1) {
         args.GetReturnValue().Set( except("You must provide one argument.") );
				 return;
		}

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}
    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void fresh(const FunctionCallbackInfo<v8::Value> &args) {
	  Isolate *isolate = v8::Isolate::GetCurrent();
	  v8::EscapableHandleScope handle_scope(isolate);

		if (args.Length() < 1) {
         args.GetReturnValue().Set( except("You must provide one argument.") );
				 return;
		}

    Local<Object> target = args[0]->ToObject();

		if(!Buffer::HasInstance(target)) {
		 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
		 return;
		}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void jh(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);


	if (args.Length() < 1) {
			 args.GetReturnValue().Set( except("You must provide one argument.") );
			 return;
	}

	Local<Object> target = args[0]->ToObject();

	if(!Buffer::HasInstance(target)) {
	 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
	 return;
	}

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    jh_hash(input, output, input_len);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void c11(const FunctionCallbackInfo<v8::Value> &args) {
	Isolate *isolate = v8::Isolate::GetCurrent();
	v8::EscapableHandleScope handle_scope(isolate);

	if (args.Length() < 1) {
			 args.GetReturnValue().Set( except("You must provide one argument.") );
			 return;
	}

	Local<Object> target = args[0]->ToObject();

	if(!Buffer::HasInstance(target)) {
	 args.GetReturnValue().Set( except("Argument should be a buffer object.") );
	 return;
	}


    char * input = Buffer::Data(target);
    char output[32];

  //  uint32_t input_len = Buffer::Length(target);

    c11_hash(input, output);

		Local<ArrayBuffer> buff = ArrayBuffer::New(isolate, output, 32);
		args.GetReturnValue().Set(  handle_scope.Escape(buff) );
}

void init(Handle<Object> exports) {
	  	Isolate *isolate = v8::Isolate::GetCurrent();
    exports->Set(String::NewFromUtf8(isolate,"quark"), FunctionTemplate::New(isolate,quark)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"x11"), FunctionTemplate::New(isolate,x11)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"scrypt"), FunctionTemplate::New(isolate,scrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"scryptn"), FunctionTemplate::New(isolate,scryptn)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"scryptjane"), FunctionTemplate::New(isolate,scryptjane)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"yescrypt"), FunctionTemplate::New(isolate,yescrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"keccak"), FunctionTemplate::New(isolate,keccak)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"bcrypt"), FunctionTemplate::New(isolate,bcrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"skein"), FunctionTemplate::New(isolate,skein)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"groestl"), FunctionTemplate::New(isolate,groestl)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"groestlmyriad"), FunctionTemplate::New(isolate,groestlmyriad)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"blake"), FunctionTemplate::New(isolate,blake)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"fugue"), FunctionTemplate::New(isolate,fugue)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"qubit"), FunctionTemplate::New(isolate,qubit)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"hefty1"), FunctionTemplate::New(isolate,hefty1)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"shavite3"), FunctionTemplate::New(isolate,shavite3)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"cryptonight"), FunctionTemplate::New(isolate,cryptonight)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"x13"), FunctionTemplate::New(isolate,x13)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"x14"), FunctionTemplate::New(isolate,x14)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"boolberry"), FunctionTemplate::New(isolate,boolberry)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"nist5"), FunctionTemplate::New(isolate,nist5)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"sha1"), FunctionTemplate::New(isolate,sha1)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"x15"), FunctionTemplate::New(isolate,x15)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"fresh"), FunctionTemplate::New(isolate,fresh)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"s3"), FunctionTemplate::New(isolate,s3)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"neoscrypt"), FunctionTemplate::New(isolate,neoscrypt_hash)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"dcrypt"), FunctionTemplate::New(isolate,dcrypt)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"jh"), FunctionTemplate::New(isolate,jh)->GetFunction());
    exports->Set(String::NewFromUtf8(isolate,"c11"), FunctionTemplate::New(isolate,c11)->GetFunction());
}

NODE_MODULE(multihashing, init)

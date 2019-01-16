#ifndef SERVER_H
#define SERVER_H

#include <nan.h>
#include <virgil/crypto/phe/vsce_phe_server.h>

#include "utils.h"

class Server : public Nan::ObjectWrap {
public:
  static void Init(v8::Local<v8::Object> exports);
private:
  static void New(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void GenerateServerKeyPair(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void GetEnrollment(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void VerifyPassword(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static void RotateKeys(const Nan::FunctionCallbackInfo<v8::Value>& info);
  static Nan::Persistent<v8::Function> constructor;
  Server();
  ~Server();
  vsce_phe_server_t* phe_server;
};

#endif
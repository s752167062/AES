//
//  AESUtil.hpp
//  GameChess
//
//  Created by yajing on 2018/7/16.
//

#ifndef AESUtil_hpp
#define AESUtil_hpp

#include "cocos2d.h"
#include <string>
#include "tolua_fix.h"
#include "CCLuaStack.h"
#include "CCLuaValue.h"
#include "CCLuaEngine.h"

using namespace std ;
USING_NS_CC ;

class AESUtil{
public:
    static AESUtil * getInstance();
    AESUtil();
    virtual ~AESUtil();
   
    static int cpp_AESDecode(lua_State* ls);
    void bind(lua_State *ls);
    
    //转码的
    int hexCharToInt(char c);
    char* hexstringToBytes(std::string s);
    std::string bytestohexstring(char* bytes,int bytelength);
    
    char* rtrim_lc(char* s);
    
    //demo
    void aesTest();

};
#endif /* AESUtil_hpp */

//
//  AESUtil.hpp
//  GameChess
//
//  Created by yajing on 2018/7/16.
//

#ifndef AESUtil_hpp
#define AESUtil_hpp


#include <string>
using namespace std ;

class AESUtil{
public:
    static AESUtil * getInstance();
    AESUtil();
    virtual ~AESUtil();
   
    
    //转码的
    int hexCharToInt(char c);
    char* hexStringToBytes(std::string s);
    string bytesToHexString(char* bytes,int bytelength);

    string AES_ECBEncode(string data , string key);
    string AES_ECBDecode(string data , string key);
    
    string AES_CBCEncode(string data , string key , string fixkey);
    string AES_CBCDecode(string data , string key , string fixkey);

    //demo
    void aesTest();

};
#endif /* AESUtil_hpp */

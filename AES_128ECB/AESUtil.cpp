//
//  AESUtil.cpp
//  GameChess
//
//  Created by yajing on 2018/7/16.
//

#include "AESUtil.h"
#include <openssl/aes.h>

static AESUtil * instance = nullptr ;
AESUtil* AESUtil::getInstance(){
    if (instance == nullptr) {
        instance = new AESUtil();
    }
    return instance ;
}

AESUtil::AESUtil(){
    CCLOG("**** 创建AES解密 ****");
}

void AESUtil::bind(lua_State *ls)
{
    lua_register(ls, "cpp_urNetDecode"        , cpp_AESDecode);
}

int AESUtil::cpp_AESDecode(lua_State *ls){
    try{
        string data     = lua_tostring(ls, 1);
        string key_code = lua_tostring(ls, 2);
        
        if (data.empty() || key_code.empty()) {
            lua_settop(ls, 0);
            lua_pushstring(ls, "");
            lua_pushstring(ls, "数据or解密key为空");
            return 2;
        }
        
        const char* encode_data = data.c_str();
        const char* decode_key  = key_code.c_str();
        int length = (((strlen(encode_data) +AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE )/2;  //对齐分组  原始数据长度 = 加密后的16进制数据长度/2
        
        printf(">>>> 原始加密数据   : %s\n" ,encode_data);
        printf(">>>> 原始加密数据长度 : %d\n",length);
        
        //16进制的原始数转
        char * hex_encode_data = AESUtil::getInstance()->hexstringToBytes(data);
        printf(">>>> 原始加密数据 hex to bytes >> : %s\n",hex_encode_data);
        
        //解密key
        char userkey[AES_BLOCK_SIZE];
        memcpy(userkey, decode_key ,AES_BLOCK_SIZE);
        
        //解密后的数据保存位置
        char * decrypt_result = NULL;
        decrypt_result = (char *)calloc(length+1, sizeof(char));
        
        //AES KEY  秘钥长度128 = 16*8
        AES_KEY key;
        memset(&key, 0x00, sizeof(AES_KEY));
        int status = AES_set_decrypt_key((unsigned char*)userkey, AES_BLOCK_SIZE * 8, &key);
        if(status < 0){
            printf(">>>> AES_set_decrypt_key err\n");
            lua_settop(ls, 0);
            lua_pushstring(ls, "");
            lua_pushstring(ls, "set_decrypt_key err");
            return 2;
        }
        
        /*循环解密*/
        int len = 0;
        while(len < length) {
            //        AES_decrypt((unsigned char*) (newenc+len), (unsigned char*)(decrypt_result+len), &key);
            AES_ecb_encrypt((unsigned char*)hex_encode_data +len , (unsigned char*)decrypt_result +len, &key, AES_DECRYPT);
            len += AES_BLOCK_SIZE;
        }
        printf(">>>> 解密结果：%s\n",decrypt_result);
        
        lua_settop(ls, 0);
        lua_pushstring(ls, decrypt_result);
        lua_pushstring(ls, "");
        return 2;
        
    }catch(exception err){
        printf(">>>> err try : %s",err.what());
        lua_settop(ls, 0);
        lua_pushstring(ls, "");
        lua_pushstring(ls, "解析异常");
        return 2;
    }
}

AESUtil::~AESUtil(){
    CCLOG("**** HTTP Utils 释放 ****");
    if(nullptr != instance){
        delete instance;
        instance = nullptr;
    }
}

/**
 十六进制的转换
 */
int AESUtil::hexCharToInt(char c)
{
    if (c >= '0' && c <= '9') return (c - '0');
    if (c >= 'A' && c <= 'F') return (c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return (c - 'a' + 10);
    return 0;
}

char* AESUtil::hexstringToBytes(string s)
{
    int sz = s.length();
    char *ret = new char[sz/2];
    for (int i=0 ; i <sz ; i+=2) {
        ret[i/2] = (char) ((hexCharToInt(s.at(i)) << 4)
                           | hexCharToInt(s.at(i+1)));
    }
    return ret;
}

string AESUtil::bytestohexstring(char* bytes,int bytelength)
{
    string str("");
    string str2("0123456789abcdef");
    for (int i=0;i<bytelength;i++) {
        int b;
        b = 0x0f&(bytes[i]>>4);
        char s1 = str2.at(b);
        str.append(1,str2.at(b));
        b = 0x0f & bytes[i];
        str.append(1,str2.at(b));
        char s2 = str2.at(b);
    }
    return str;
}



/*
 AES ECB 模式 秘钥长度128   PKCS5Paddig补码方式  ， 解密串编码方式：16进制
 
 参考 ：http://www.seacha.com/tools/aes.html
 
 */
void AESUtil::aesTest(){
    char *data = "[{\"outsideNetworkIp\":\"10.186.75.1\",\"internalNetworkIp\":\"192.168.0.7\",\"gatewayAddressName\":\"7号网关服务器\",\"crttime\":1529400703000,\"remark\":\"7号为被备用服务器\",\"del\":0,\"id\":7},{\"outsideNetworkIp\":\"10.186.75.1\",\"internalNetworkIp\":\"192.168.0.8\",\"gatewayAddressName\":\"8号网关服务器\",\"crttime\":1529658896000,\"remark\":\"8号网关服务器！！！\",\"del\":0,\"id\":9}]"; //接收参数
    int length = ((strlen(data)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;  //对齐分组
    
    printf(">>>> 原始数据：%s\n",data);
    printf(">>>> 原始数据长度: %d",length);
    
    char userkey[AES_BLOCK_SIZE];
    
    char *encrypt_result = NULL;
    encrypt_result = (char *)calloc(length+1, sizeof(char));
    
    char *decrypt_result = NULL;
    decrypt_result = (char *)calloc(length+1, sizeof(char));
    
    AES_KEY key;
    memset(&key, 0x00, sizeof(AES_KEY));
    memcpy(userkey,"ssd6ka8qgle3vpjc",AES_BLOCK_SIZE);
    
    AES_set_encrypt_key((unsigned char*)userkey, AES_BLOCK_SIZE*8, &key);
    printf(">>>> 加密密钥：%d\n",key);
    
    int len = 0;
    /*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
    while(len < length) {
        AES_encrypt((unsigned char*)(data+len), (unsigned char*)(encrypt_result+len), &key);
        len += AES_BLOCK_SIZE;
    }
    printf("加密结果：%s\n",encrypt_result);
    
    //hex
    string str = bytestohexstring(encrypt_result , length);
    printf("hex >> : %s\n",str.c_str());
    
    
    
    //使用
    string str_ = "b30eb5134149c5ac8b68b746345670a0bc6001cf08682ce5bc0c1b157036de671041578f7e358773e00677e08aaa639d205537ea12d2c10dd63b2a2ce9a03aabba9407ddf6a97ad90b6c274a24257c775b8725055afd61903a014c6810a29396fabd11ad220482b28d0e6d370c408bf566f34b1d06cafaec53acc0bb4f2f1ab37daa6b3a51749f97d64d5dff6be4ac9e47f97b4f1beab0c523fdc511e8e446cfac6398102d684bbc1f828ac3f70b3f13aa255c6192dc27808ae3d13831726309c2f51d9414be817519b1661797bd266fbf383e678f6b085ba2638526d2e8c2c7bd1a3d065ffea6dadd24f54f3d9e1798a2f7e4b1176b69cad353c8713046ecc40c00d5144c313e95cfefaac79e0c5032a37b70b8b97d33c48878a188cb94f9fc524a016be12fe235f3de18b03545a8eaf191a19fb8afb1f9ee2f7c708fff4abe4f57ea40553829ccec7f5cead2101ef23cbfb63ec413e50c46a4fb78e046d6b8da828c574bf2086028a3d07a6368523335ba1ba01888b90a3e93b0bc5ecfe0a5";
    int length_str = ((strlen(str_.c_str())+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;  //对齐分组
    printf(">>>> hex数据长度: %d",length_str);
    char * newenc_ = hexstringToBytes(str_);
    printf("str_ hex to bytes >> : %s\n",newenc_);
    
    char * newenc = hexstringToBytes(str);
    printf("hex to bytes >> : %s\n",newenc);
    
    
    
    memset(&key, 0x00, sizeof(AES_KEY));
    AES_set_decrypt_key((unsigned char*)userkey, AES_BLOCK_SIZE*8, &key);
    printf("解密密钥：%d\n",key);
    len = 0;
    /*循环解密*/
    while(len < length) {
        //        AES_decrypt((unsigned char*) (newenc+len), (unsigned char*)(decrypt_result+len), &key);
        AES_ecb_encrypt((unsigned char*)newenc+len , (unsigned char*)decrypt_result +len, &key, AES_DECRYPT);
        len += AES_BLOCK_SIZE;
    }
    
    printf("解密结果：%s\n",decrypt_result);
    
}

////操作
//去掉字符串尾(右)空格函数
char* AESUtil::rtrim_lc(char* s)
{
    char* s_s=new char[strlen(s)+1];
    strcpy(s_s,s);
    //
    int s_len=strlen(s_s);
    for(int i=s_len-1;i>=0;i--)
    {
        if(s_s[i]==' ')
        {
            s_s[i]='\0';
        }
    }
    char* d_s=new char[strlen(s_s)];
    strcpy(d_s,s_s);
    return d_s;
}




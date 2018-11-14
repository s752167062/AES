//
//  AESUtil.cpp
//  GameChess
//
//  Created by yajing on 2018/7/16.
//
/**
    校验网站 http://www.seacha.com/tools/aes.html
    密钥长度 128
    补码方式 PKCS5Padding
    加密结果编码方式 十六进制

    AES 加密是每次加密16位 ，不足16位的需要进行补码，补的内容为缺少的位数 ，如果位数是16的倍数那么补的内容是 16 详细看代码
    如果补码不正确会出现说 前面的数据是对的后面的对不上 ，实际就是后面补码的内容出现问题或者没有补码
*/
#include "AESUtil.h"
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static AESUtil * instance = nullptr ;
AESUtil* AESUtil::getInstance(){
    if (instance == nullptr) {
        instance = new AESUtil();
    }
    return instance ;
}

AESUtil::AESUtil(){
    
}

AESUtil::~AESUtil(){
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

char* AESUtil::hexStringToBytes(string s)
{
    int sz = s.length();
    char *ret = new char[sz/2];
    for (int i=0 ; i <sz ; i+=2) {
        ret[i/2] = (char) ((hexCharToInt(s.at(i)) << 4)
                           | hexCharToInt(s.at(i+1)));
    }
    return ret;
}

string AESUtil::bytesToHexString(char* bytes,int bytelength)
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


/* AES ECB 解密 AES_ecb_encrypt 函数在源码里面实际调用的就是 AES_encrypt */
string AESUtil::AES_ECBDecode(string data, string keyCode){
    const char* encode_data = data.c_str();
    const char* decode_key  = keyCode.c_str();
    int length = (((strlen(encode_data) +AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE )/2;  //对齐分组  原始数据长度 = 加密后的16进制数据长度/2
    
    printf(">>>> 原始加密数据   : %s\n" ,encode_data);
    printf(">>>> 原始加密数据长度 : %d\n",length);
    
    //16进制的原始数转
    char * hex_encode_data = this->hexStringToBytes(data);
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
        return nullptr;
    }
    
    /*循环解密*/
    int len = 0;
    while(len < length) {
        AES_ecb_encrypt((unsigned char*)hex_encode_data +len , (unsigned char*)decrypt_result +len, &key, AES_DECRYPT);
        len += AES_BLOCK_SIZE;
    }
    printf(">>>> 解密结果：%s\n",decrypt_result);
    return decrypt_result;
}

// ECB 加密 
string AESUtil::AES_ECBEncode(string data , string keyCode){
    const char* decode_data = data.c_str();
    const char* decode_key  = keyCode.c_str();
    int length = ((strlen(decode_data) /AES_BLOCK_SIZE +1 )*AES_BLOCK_SIZE ) ;  //对齐分组
    
    printf(">>>> 原始数据：%s\n" ,decode_data);
    printf(">>>> 原始数据长度: %d"  ,length);
    
    
    //解密key
    char userkey[AES_BLOCK_SIZE];
    memcpy(userkey, decode_key ,AES_BLOCK_SIZE);
    
    //解密后的数据保存位置
    char * encrypt_result = NULL;
    encrypt_result = (char *)calloc(length+1, sizeof(char));
    
    //AES KEY  秘钥长度128 = 16*8
    AES_KEY key;
    memset(&key, 0x00, sizeof(AES_KEY));
    int status = AES_set_encrypt_key((unsigned char*)userkey, AES_BLOCK_SIZE * 8, &key);
    if(status < 0){
        printf(">>>> AES_set_decrypt_key err\n");
        return nullptr;
    }
    
    //内容补码操作 补的内容为缺的位数， 是16的倍数的话全用16
    int data_length = strlen(decode_data) ;
    char * data_n = (char*)malloc(length);
    int nNumber;
    if (data_length % 16 > 0){
        nNumber = length - data_length;
    }else{
        nNumber = 16;
    }
    printf(">>>> 补码 : %d",nNumber);
    memset(data_n, nNumber, length);
    memcpy(data_n, decode_data, data_length);
    
    int len = 0;
    /*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
    while(len < length) {
        AES_ecb_encrypt((unsigned char*)(data_n+len), (unsigned char*)(encrypt_result+len), &key ,AES_ENCRYPT);
        len += AES_BLOCK_SIZE;
    }
    printf("加密结果：%s\n",encrypt_result);
    
    return this->bytesToHexString(encrypt_result, length);
}


// CBC模式加密
string AESUtil::AES_CBCEncode(string data , string keyCode , string fixkey){
    const char * encode_data = data.c_str();
    const char * key_code = keyCode.c_str();
    const char * fix_key  = fixkey.c_str();
    
    int data_length = strlen(encode_data);
    int length = (data_length / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    
    //补码计算
    int nNumber;
    if (data_length % 16 > 0){
        nNumber = length - data_length;
    }else{
        nNumber = 16;
    }
    printf(">>>> 补码 : %d",nNumber);
    
    char * data_en = (char*)malloc(length);
    memset(data_en, nNumber, length);
    memcpy(data_en, encode_data, data_length);
    
    //解密后的数据保存位置
    char * encrypt_result = NULL;
    encrypt_result = (char *)calloc(length+1, sizeof(char));

    //
    AES_KEY key;

    if (AES_set_encrypt_key((unsigned char*)key_code, AES_BLOCK_SIZE * 8, &key) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        return nullptr;
    }
    
    AES_cbc_encrypt((unsigned char *)data_en, (unsigned char*)encrypt_result, length, &key, (unsigned char*)fix_key, AES_ENCRYPT);
    
    return this->bytesToHexString((char *)encrypt_result, length );
}

// CBC模式解密
string AESUtil::AES_CBCDecode(string data , string keyCode , string fixkey){
    const char * decode_data = data.c_str();
    const char * key_code = keyCode.c_str();
    const char * fix_key  = fixkey.c_str();
    
    int data_length = strlen(decode_data) /2;
    char * hex_data = this->hexStringToBytes(data);
    //key
    AES_KEY key;
    if (AES_set_decrypt_key((unsigned char*)key_code, AES_BLOCK_SIZE * 8, &key) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        return nullptr;
    }
    
    char * decrypt_result = NULL;
    decrypt_result = (char *)calloc(data_length+1, sizeof(char));
    
    
    AES_cbc_encrypt((unsigned char *)hex_data, (unsigned char*)decrypt_result,  data_length, &key, (unsigned char*)fix_key, AES_DECRYPT);
    return decrypt_result;
    
}


/*
 AES ECB 模式 秘钥长度128   PKCS5Paddig补码方式  ， 解密串编码方式：16进制
 
 参考 ：http://www.seacha.com/tools/aes.html
 
 */
//void AESUtil::aesTest(){
//    char *data = "01234567890123456789012345678900"; //接收参数
//    int length = (strlen(data)/AES_BLOCK_SIZE +1 )*AES_BLOCK_SIZE;  //对齐分组
//    
//    printf(">>>> 原始数据：%s\n",data);
//    printf(">>>> 原始数据长度: %d",length);
//    
//    char userkey[AES_BLOCK_SIZE];
//    
//    char *encrypt_result = NULL;
//    encrypt_result = (char *)calloc(length+1, sizeof(char));
//    
//    char *decrypt_result = NULL;
//    decrypt_result = (char *)calloc(length+1, sizeof(char));
//    
//    AES_KEY key;
//    memset(&key, 0x00, sizeof(AES_KEY));
//    memcpy(userkey,"ssd6ka8qgle3vpjc",AES_BLOCK_SIZE);
//    
////    char data_n[length];
////    memset(data_n, 0, sizeof(data_n));
////    strcpy(data_n, data);
//    
//    int nBei1 = strlen(data) / AES_BLOCK_SIZE + 1;
//    int nTotal1 = nBei1 * AES_BLOCK_SIZE;
//    char * data_n = (char*)malloc(nTotal1);
//    int nNumber1;
//
//    if (strlen(data) % 16 > 0)
//        nNumber1 = nTotal1 - strlen(data);
//    else
//        nNumber1 = 16;
//    
//    printf(">>>> nNumber1: %d",nNumber1);
//    memset(data_n, nNumber1, nTotal1);
//    memcpy(data_n, data, strlen(data));
//    
//    
//    memset(encrypt_result, 0, sizeof(encrypt_result));
//    
//    
//    AES_set_encrypt_key((unsigned char*)userkey, AES_BLOCK_SIZE*8, &key);
//    printf(">>>> 加密密钥：%d\n",key);
//    
//    int len = 0;
//    /*循环加密，每次只能加密AES_BLOCK_SIZE长度的数据*/
//    while(len < length) {
//        AES_ecb_encrypt((unsigned char*)(data_n+len), (unsigned char*)(encrypt_result+len), &key ,AES_ENCRYPT);
//        len += AES_BLOCK_SIZE;
//    }
//    printf("加密结果：%s\n",encrypt_result);
//    
//    string hex_encode_data3 = bytestohexstring((char *)encrypt_result, length );
//    printf(">>>> 加密数据 hex 啊啊啊 >> : %s\n",hex_encode_data3.c_str());
//    //hex操作 or base64
//    
//    memset(&key, 0x00, sizeof(AES_KEY));
//    AES_set_decrypt_key((unsigned char*)userkey, AES_BLOCK_SIZE*8, &key);
//    printf("解密密钥：%d\n",key);
//    len = 0;
//    /*循环解密*/
//    while(len < length) {
//        //        AES_decrypt((unsigned char*) (newenc+len), (unsigned char*)(decrypt_result+len), &key);
//        AES_ecb_encrypt((unsigned char*)encrypt_result+len , (unsigned char*)decrypt_result +len, &key, AES_DECRYPT);
//        len += AES_BLOCK_SIZE;
//    }
//    
//    printf("解密结果：%s\n",decrypt_result);
//
//    
//    //
////    string encdoe = EncodeAES("ssd6ka8qgle3vpjc" , "01234567890123456789012345678900");
////    string hex_encode_data = bytestohexstring((char *)encdoe.c_str(), length );
////    printf(">>>> 加密数据 hex >> : %s\n",hex_encode_data.c_str());
//    
//    
//    char encrypt_string[4096] = { 0 };
//    AES_KEY aes;
//    char key2[17] = "ssd6ka8qgle3vpjc";
//    char iv[17] = "abcdefgh3762quck";
//    std::string input_string = "01234567890123456789012345678900";
//    int nLen = input_string.length();
//    
//    int nBei = nLen / AES_BLOCK_SIZE + 1;
//    int nTotal = nBei * AES_BLOCK_SIZE;
//    char *enc_s = (char*)malloc(nTotal);
//    int nNumber;
//    if (nLen % 16 > 0)
//        nNumber = nTotal - nLen;
//    else
//        nNumber = 16;
//    memset(enc_s, nNumber, nTotal);
//    memcpy(enc_s, input_string.data(), nLen);
//    
//    if (AES_set_encrypt_key((unsigned char*)key2, 128, &aes) < 0) {
//        fprintf(stderr, "Unable to set encryption key in AES\n");
//        exit(-1);
//    }
//    
//    AES_cbc_encrypt((unsigned char *)enc_s, (unsigned char*)encrypt_string, nBei * 16, &aes, (unsigned char*)iv, AES_ENCRYPT);
//    
//    
//    string hex_encode_data2 = bytestohexstring((char *)encrypt_string, length );
//    printf(">>>> 加密数据 hex >> : %s\n",hex_encode_data2.c_str());
//    
//    if (AES_set_decrypt_key((unsigned char*)key2, 128, &aes) < 0) {
//        fprintf(stderr, "Unable to set decryption key in AES\n");
//        exit(-1);
//    }
//    char decrypt_string[4096] = { 0 };
//    char ivd[17] = "abcdefgh3762quck";
////    string ddd = "51a125a89d2c988927e5236da314473e6439986ee69b02bc40efa20da4653f0cbee999605f63a42a4f624148394fff7a";
////    char * fff = hexstringToBytes(ddd);
//    AES_cbc_encrypt((unsigned char *)encrypt_string, (unsigned char*)decrypt_string,  nBei * 16, &aes, (unsigned char*)ivd, AES_DECRYPT);
//    printf(">>>> 解密数据 hex >> : %s\n",decrypt_string);
//
//}
//
//////操作
////去掉字符串尾(右)空格函数
//char* AESUtil::rtrim_lc(char* s)
//{
//    char* s_s=new char[strlen(s)+1];
//    strcpy(s_s,s);
//    //
//    int s_len=strlen(s_s);
//    for(int i=s_len-1;i>=0;i--)
//    {
//        if(s_s[i]==' ')
//        {
//            s_s[i]='\0';
//        }
//    }
//    char* d_s=new char[strlen(s_s)];
//    strcpy(d_s,s_s);
//    return d_s;
//}





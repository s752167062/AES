//
//  main.m
//  OpensslAES
//
//  Created by yajing on 2018/11/14.
//  Copyright © 2018年 yajing. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "AESUtil.h"
int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        NSLog(@"Hello, World!");
    }
    
    string data = "12345678901234567890123456789000";
    string key  = "qwertyuiopasdfgh";
    string result = AESUtil::getInstance()->AES_ECBEncode(data, key);
    printf("@@@ 加密结果  : %s @@@", result.c_str());
    
    string d_result = AESUtil::getInstance()->AES_ECBDecode(result, key);
    printf("@@@ 解密结果  : %s @@@", d_result.c_str());
    
    
    string cbcdata = "12345678901234567890123456789012";
    string cbckey = "1234567890123456";
    string fixkey = "qwertyuiopasdfgh";
    string cbcresult = AESUtil::getInstance()->AES_CBCEncode(cbcdata, cbckey, fixkey);
    printf("@@@ cbc 加密结果  %s @@@" , cbcresult.c_str());
    
    string cbcdresult = AESUtil::getInstance()->AES_CBCDecode(cbcresult, cbckey, fixkey);
    printf("@@@ cbc 解密结果  %s @@@" , cbcdresult.c_str());
    
    return 0;
}

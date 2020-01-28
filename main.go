package main

import(
	"fmt"
	"OES"
)

func main() {
	//生成
	autoUPW, autoLOW := OES.Even(9)
	fmt.Println("加密钥匙：" + autoUPW)
	fmt.Println("解密钥匙：" + autoLOW)

	//验证
	fmt.Println(OES.Auto(autoUPW, autoLOW))

	//被加密的字符串
	fmt.Println("字符串: Hello")

	//使用加密钥匙加密文本
	uSTR := OES.UPW("Hello",autoUPW)
	fmt.Println("加密后："+uSTR)

	//解密字符串Hello
	fmt.Println("解密后: "+OES.LOW(uSTR, autoLOW))

}
package OES

import (
	"DES"
	"STR"
)

//生成（生成一对密钥）
func Even(number int) (string, string) {
	UPW := STR.HitCode(number)  //加密钥匙
	upwAuto := STR.HitCode(8)  //加密钥匙 配对值

	LOW := DES.Encrypt(UPW, upwAuto)  //解密钥匙 [ 加密钥匙 authcode 配对值 ]
	lowAuto := STR.HitCode(8)  //解密钥匙 配对值

	//对密钥进行混淆
	UPW = lowAuto + UPW   //解密钥匙 配对值 + 加密钥匙  / 加密
	LOW = LOW + upwAuto   //解密钥匙 + 加密钥匙配对值   / 解密

	return UPW, LOW
}

//配对（检查公钥私钥）
func Auto(UPW string, LOW string) bool {

	lenLOW := len(LOW)
	lenUPW := len(UPW)

	autoNum := LOW[32:lenLOW]  //配对值
	LOW = LOW[0:32]            //真实的  解密钥匙
	UPW = UPW[8:lenUPW]           //真实的  加密钥匙

	LOW = DES.Decrypt(LOW, autoNum)

	if UPW == LOW {
		return true
	}

	return false
}

//加密
func UPW(STR string, UPW string) string {
	return DES.Encrypt(STR, UPW[9:len(UPW)])
}

//解密
func LOW(STR string, LOW string) string {

	autoNum := LOW[32:len(LOW)]  //配对值
	LOW = LOW[0:32]            //真实的  解密钥匙

	keyLock := DES.Decrypt(LOW,autoNum)

	return DES.Decrypt(STR, keyLock[1:9])

}

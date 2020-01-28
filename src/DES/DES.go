package DES

import (
	"encoding/hex"
	"os"
	"strconv"
)

func Encrypt(clear_text, key string) string {
	extra := 8 - len(clear_text)%8
	for i := 0; i < extra; i++ {
		clear_text = clear_text + string('0'+extra)
	}
	clear_text = hex.EncodeToString([]byte(clear_text))
	return hexText(des(clear_text, key, true))
}

func Decrypt(cipher_text, key string) string {
	clear_text_hex := hexText(des(cipher_text, key, false))
	clear_text, _ := hex.DecodeString(clear_text_hex)
	clear_text_len := len(clear_text)
	return string(clear_text[:clear_text_len-int(clear_text[clear_text_len-1]-'0')])
}

/** 不公开 DES 函数 **/
func des(text, key string, tag bool) string {
	if len(key) != 8 {
		//fmt.Println("The secret key need to be 8 bits.")
		os.Exit(0)
	}
	key = formatKey(key)
	keys := getKeys(key)
	final_text := ""
	if !tag {
		keys = reverse(keys)
	}
	for i := 0; i < len(text)/16; i++ {
		textSub := binText(text[i*16 : i*16+16])
		text_init_replace := initialReplace(textSub)
		R_16_L_16 := iteration(text_init_replace, keys)
		final_text += reverseReplace(R_16_L_16)
	}
	return final_text
}

func decimalToBinary(data int) string {
	switch data {
	case 0:
		return "0000"
	case 1:
		return "0001"
	case 2:
		return "0010"
	case 3:
		return "0011"
	case 4:
		return "0100"
	case 5:
		return "0101"
	case 6:
		return "0110"
	case 7:
		return "0111"
	case 8:
		return "1000"
	case 9:
		return "1001"
	case 10:
		return "1010"
	case 11:
		return "1011"
	case 12:
		return "1100"
	case 13:
		return "1101"
	case 14:
		return "1110"
	case 15:
		return "1111"
	}
	return ""
}

func hexadecimalToBinary(data byte) string {
	switch data {
	case '0':
		return "0000"
	case '1':
		return "0001"
	case '2':
		return "0010"
	case '3':
		return "0011"
	case '4':
		return "0100"
	case '5':
		return "0101"
	case '6':
		return "0110"
	case '7':
		return "0111"
	case '8':
		return "1000"
	case '9':
		return "1001"
	case 'a':
		return "1010"
	case 'b':
		return "1011"
	case 'c':
		return "1100"
	case 'd':
		return "1101"
	case 'e':
		return "1110"
	case 'f':
		return "1111"
	}
	return ""
}

func reverse(keys []string) []string {
	keys_reverse := make([]string, 0)
	for i := len(keys) - 1; i >= 0; i-- {
		keys_reverse = append(keys_reverse, keys[i])
	}
	return keys_reverse
}

func formatKey(key string) string {
	hexKey := hex.EncodeToString([]byte(key))
	binKey := ""
	for i := 0; i < len(hexKey); i++ {
		binKey += hexadecimalToBinary(hexKey[i])
	}
	return binKey
}

func binText(text string) string {
	binText := ""
	for i := 0; i < len(text); i++ {
		binText += hexadecimalToBinary(text[i])
	}
	return binText
}

func hexText(text string) string {
	hexText := ""
	for i := 0; i < len(text)/4; i++ {
		dec_text, _ := strconv.ParseInt(text[i*4:i*4+4], 2, 64)
		hexText += strconv.FormatInt(dec_text, 16)
	}
	return hexText
}

var initial_replace_matrix = [8][8]int{
	{58, 50, 42, 34, 26, 18, 10, 2},
	{60, 52, 44, 36, 28, 20, 12, 4},
	{62, 54, 46, 38, 30, 22, 14, 6},
	{64, 56, 48, 40, 32, 24, 16, 8},
	{57, 49, 41, 33, 25, 17, 9, 1},
	{59, 51, 43, 35, 27, 19, 11, 3},
	{61, 53, 45, 37, 29, 21, 13, 5},
	{63, 55, 47, 39, 31, 23, 15, 7},
}

var pc_1 = [56]int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var pc_2 = [48]int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var extended_replacement_matrix = [8][6]int{
	{32, 1, 2, 3, 4, 5},
	{4, 5, 6, 7, 8, 9},
	{8, 9, 10, 11, 12, 13},
	{12, 13, 14, 15, 16, 17},
	{16, 17, 18, 19, 20, 21},
	{20, 21, 22, 23, 24, 25},
	{24, 25, 26, 27, 28, 29},
	{28, 29, 30, 31, 32, 1},
}

var s_box = [8][4][16]int{
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

var p_box = [32]int{
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
}

var reverse_replace = [64]int{
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
}

var displacements = [16]int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

func getInitialReplaceMatrix() [8][8]int {
	return initial_replace_matrix
}

func getExtendedReplacementMatrix() [8][6]int {
	return extended_replacement_matrix
}

func getCN(round int) []int {
	displacement := getDisplacements(round)
	CN := make([]int, 28-displacement)
	copy(CN, pc_1[displacement:28])
	for i := 0; i < displacement; i++ {
		CN = append(CN, pc_1[i])
	}
	return CN
}

func getDN(round int) []int {
	displacement := getDisplacements(round)
	DN := make([]int, 28-displacement)
	copy(DN, pc_1[28+displacement:])
	for i := 0; i < displacement; i++ {
		DN = append(DN, pc_1[28+i])
	}
	return DN
}

func getCNDN(round int) []int {
	CNDN := getCN(round)
	DN := getDN(round)
	for _, ele := range DN {
		CNDN = append(CNDN, ele)
	}
	return CNDN
}

func replace(CNDN []int, key string) string {

	initial_cipher_code_replace := ""
	for i := 0; i < 56; i++ {
		initial_cipher_code_replace += string(key[CNDN[i]-1])
	}

	cipher_code_replace := ""
	for i := 0; i < 48; i++ {
		cipher_code_replace += string(initial_cipher_code_replace[pc_2[i]-1])
	}

	return cipher_code_replace
}

func getCipherCodeN(round int, key string) string {
	CNDN := getCNDN(round)
	return replace(CNDN, key)
}

func getKeys(key string) []string {
	// Encryption processing
	keys := make([]string, 0)
	for i := 1; i <= 16; i++ {
		keys = append(keys, getCipherCodeN(i, key))
	}
	return keys
}

func getDisplacements(round int) int {
	displacement := 0
	for i := 0; i < round; i++ {
		displacement += displacements[i]
	}
	return displacement
}

func getSBoxN(index int) [4][16]int {
	return s_box[index]
}

func getPBox() [32]int {
	return p_box
}

func getReverseReplace() [64]int {
	return reverse_replace
}

func getRow(num1, num2 byte) int {
	row, _ := strconv.ParseInt(string(num1)+string(num2), 2, 64)
	return int(row)
}

func getColumn(column string) int {
	col, _ := strconv.ParseInt(column, 2, 64)
	return int(col)
}

func initialReplace(clear_text string) string {
	clear_text_init_replace := ""
	initial_replace_matrix := getInitialReplaceMatrix()
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			clear_text_init_replace += string(clear_text[initial_replace_matrix[i][j]-1])
		}
	}
	return clear_text_init_replace
}

func iteration(clear_text_init_replace string, keys []string) string {
	L := make([]string, 0)
	R := make([]string, 0)
	L = append(L, clear_text_init_replace[:32])
	R = append(R, clear_text_init_replace[32:])
	for k := 0; k < 16; k++ {
		// Extended replacement
		R_extended := extendedReplacement(R[k])
		// xor with keys[k]
		R_extended_xor := xorWithKeys_K(R_extended, keys[k])
		// S-box transfer
		R_extended_xor_S_trans := sBoxTransfer(R_extended_xor)
		// P-box transfer
		R_extended_xor_S_P_trans := pBoxTransfer(R_extended_xor_S_trans)
		// xor with L[k]
		R_extended_xor_S_P_trans_xor := xorWithL_K(R_extended_xor_S_P_trans, L[k])

		L = append(L, R[k])
		R = append(R, R_extended_xor_S_P_trans_xor)
	}
	R_16_L_16 := R[16] + L[16]
	return R_16_L_16
}

func extendedReplacement(R_K string) string {
	extended_replacement_matrix := getExtendedReplacementMatrix()
	width := len(extended_replacement_matrix)
	height := len(extended_replacement_matrix[0])
	R_extended := ""
	for i := 0; i < width; i++ {
		for j := 0; j < height; j++ {
			R_extended += string(R_K[extended_replacement_matrix[i][j]-1])
		}
	}
	return R_extended
}

func xorWithKeys_K(R_extended, keys_K string) string {
	R_extended_xor := ""
	for i := 0; i < len(keys_K); i++ {
		R_extended_xor += string((byte(R_extended[i]-'0') ^ byte(keys_K[i]-'0')) + '0')
	}
	return R_extended_xor
}

func sBoxTransfer(R_extended_xor string) string {
	R_extended_xor_S_trans := ""
	for i := 0; i < 8; i++ {
		R_extended_xor_slice := R_extended_xor[6*i : 6*(i+1)]
		row := getRow(R_extended_xor_slice[0], R_extended_xor_slice[5])
		column := getColumn(R_extended_xor_slice[1:5])
		S_trans_data := getSBoxN(i)[row][column]
		R_extended_xor_S_trans += decimalToBinary(S_trans_data)
	}
	return R_extended_xor_S_trans
}

func pBoxTransfer(R_extended_xor_S_trans string) string {
	R_extended_xor_S_P_trans := ""
	p_box := getPBox()
	for i := 0; i < len(p_box); i++ {
		R_extended_xor_S_P_trans += string(R_extended_xor_S_trans[p_box[i]-1])
	}
	return R_extended_xor_S_P_trans
}

func xorWithL_K(R_extended_xor_S_P_trans, L_K string) string {
	R_extended_xor_S_P_trans_xor := ""
	for i := 0; i < len(L_K); i++ {
		R_extended_xor_S_P_trans_xor += string((byte(R_extended_xor_S_P_trans[i]-'0') ^ byte(L_K[i]-'0')) + '0')
	}
	return R_extended_xor_S_P_trans_xor
}

func reverseReplace(R_16_L_16 string) string {
	// reverse replace
	cipher_text := ""
	reverse_replace := getReverseReplace()
	for i := 0; i < len(reverse_replace); i++ {
		cipher_text += string(R_16_L_16[reverse_replace[i]-1])
	}
	return cipher_text
}

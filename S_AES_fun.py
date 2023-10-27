import random

import chardet

from DF import GF
import numpy as np
import time


class S_AES:
    S_box = [[9, 4, 10, 11], [13, 1, 8, 5], [6, 2, 0, 3], [12, 14, 15, 7]]
    mix_box = [1, 4, 4, 1]
    S_box_inv = [[10, 5, 9, 11], [1, 7, 8, 15], [6, 0, 2, 3], [12, 4, 13, 14]]
    mix_box_inv = [9, 2, 2, 9]

    # 密钥加
    def key_xor(self, key, p) -> list[str]:
        res = []
        for i in range(4):
            temp_key = int(key[i], 16)
            temp_p = int(p[i], 16)
            temp = str(temp_key ^ temp_p)
            res.append(temp)
        res = np.array(res)
        return res.reshape(-1, 2)

    # 16进制补齐4位函数
    def add_4(self, str_temp) -> str:
        res = ''
        epch = 4 - len(str_temp)
        for i in range(epch):
            res += '0'
        return res + str_temp

    # 半字节替代
    def replace_res(self, input_res):
        res = []
        for i in range(2):
            for j in range(2):
                temp = int(input_res[i][j])
                # 获取二进制字符串
                str_temp = str(bin(temp)[2:])
                if len(str_temp) < 4:
                    str_temp = self.add_4(str_temp)
                # 获取二进制字符串前两位和后两位
                row = str_temp[:2]
                clo = str_temp[2:]
                res.append(str(self.S_box[int(row, 2)][int(clo, 2)]))
        res = np.array(res)
        return res.reshape(-1, 2)

    # 逆半字节替代
    def replace_res_inv(self, input_res):
        res = []
        for i in range(2):
            for j in range(2):
                temp = int(input_res[i][j])
                # 获取二进制字符串
                str_temp = str(bin(temp)[2:])
                if len(str_temp) < 4:
                    str_temp = self.add_4(str_temp)
                # 获取二进制字符串前两位和后两位
                row = str_temp[:2]
                clo = str_temp[2:]
                res.append(str(self.S_box_inv[int(row, 2)][int(clo, 2)]))
        res = np.array(res)
        return res.reshape(-1, 2)

    # 行位移
    def move_row(self, input_res) -> list[str]:
        temp = input_res[0][1]
        input_res[0][1] = input_res[1][1]
        input_res[1][1] = temp
        return input_res

    # 列混淆
    def col_mix(self, input_res):
        input_res = [[int(cell) for cell in row] for row in input_res]
        input_res = np.array(input_res).T
        gf = GF(4)
        element1 = gf.add(gf.mul(self.mix_box[0], input_res[0][0]), gf.mul(self.mix_box[1], input_res[1][0]))
        element2 = gf.add(gf.mul(self.mix_box[0], input_res[0][1]), gf.mul(self.mix_box[1], input_res[1][1]))
        element3 = gf.add(gf.mul(self.mix_box[2], input_res[0][0]), gf.mul(self.mix_box[3], input_res[1][0]))
        element4 = gf.add(gf.mul(self.mix_box[2], input_res[0][1]), gf.mul(self.mix_box[3], input_res[1][1]))
        return [[element1, element3], [element2, element4]]

    # 逆列混淆
    def col_mix_inv(self, input_res):
        input_res = [[int(cell) for cell in row] for row in input_res]
        input_res = np.array(input_res).T
        gf = GF(4)
        element1 = gf.add(gf.mul(self.mix_box_inv[0], input_res[0][0]), gf.mul(self.mix_box_inv[1], input_res[1][0]))
        element2 = gf.add(gf.mul(self.mix_box_inv[0], input_res[0][1]), gf.mul(self.mix_box_inv[1], input_res[1][1]))
        element3 = gf.add(gf.mul(self.mix_box_inv[2], input_res[0][0]), gf.mul(self.mix_box_inv[3], input_res[1][0]))
        element4 = gf.add(gf.mul(self.mix_box_inv[2], input_res[0][1]), gf.mul(self.mix_box_inv[3], input_res[1][1]))
        return [[element1, element3], [element2, element4]]

    # 获取密钥拓展每一轮的密钥
    def get_extend_key(self, input_key, num) -> str:
        input_key = self.change_16to2(input_key)
        temp_left = input_key[:8]
        temp_right = input_key[8:]
        temp_right_left = temp_right[:4]
        temp_right_right = temp_right[4:]
        temp = (str(hex(self.S_box[int(temp_right_right[:2], 2)][int(temp_right_right[2:], 2)])[-1])
                + str(hex(self.S_box[int(temp_right_left[:2], 2)][int(temp_right_left[2:], 2)]))[-1])
        if num == 0:
            key_left = int(temp_left, 2) ^ int('10000000', 2) ^ int(temp, 16)
        else:
            key_left = int(temp_left, 2) ^ int('00110000', 2) ^ int(temp, 16)
        key_right = str(hex(key_left ^ int(temp_right, 2))[2:])
        key_left = str(hex(key_left)[2:])
        return key_left.zfill(2) + key_right.zfill(2)

    # 密钥拓展
    def key_extend(self, input_key) -> list[str]:
        key_one = self.get_extend_key(input_key, 0)
        key_two = self.get_extend_key(key_one, 1)

        return [key_one, key_two]

    # 将十六进制变成二进制
    def change_16to2(self, input_str):
        res = ''
        for i in range(len(input_str)):
            temp = int(input_str[i], 16)
            str_temp = str(bin(temp)[2:])
            if len(str_temp) < 4:
                str_temp = self.add_4(str_temp)
            res += str_temp
        return res

    # 将矩阵转回16进制字符串
    def change_cov_to_str(self, cov) -> str:
        temp = ''
        for i in cov:
            for j in i:
                temp += str(hex(int(j))[2:])
        return temp

    # 将二进制变为16进制
    def binary_to_hex(self, binary_string) -> str:
        decimal = int(binary_string, 2)  # 将二进制变为十进制
        hex_string = hex(decimal)[2:]
        hex_string = self.add_4(hex_string)
        return hex_string

    # 将二进制的字符串数组变成输入的明文字符串
    def str_to_word(self, p_list):
        temp_str = ""
        for i in range(len(p_list)):
            temp_str += p_list[i]
        ascii_string = ''.join(chr(int(temp_str[i:i + 8], 2)) for i in range(0, len(temp_str), 8))
        return ascii_string

    # 16bit加密
    def encrypt(self, plain_text, secret_key):
        if len(plain_text) != 4:
            plain_text = self.binary_to_hex(plain_text)
        if len(secret_key) != 4:
            secret_key = self.binary_to_hex(secret_key)
        # 明文轮密钥加
        temp = self.key_xor(secret_key, plain_text)
        # 获取第一轮和第二轮的拓展密钥
        keys = self.key_extend(secret_key)
        # 第一轮
        temp = self.replace_res(temp)
        temp = self.move_row(temp)
        temp = self.col_mix(temp)
        temp = self.key_xor(keys[0], self.change_cov_to_str(temp))
        # 第二轮
        temp = self.replace_res(temp)
        temp = self.move_row(temp)
        temp = self.key_xor(keys[1], self.change_cov_to_str(temp))
        secret_text = self.change_16to2(self.change_cov_to_str(temp))
        return secret_text

    # 16bits解密
    def decrypt(self, secret_text, secret_key):
        if len(secret_text) != 4:
            secret_text = self.binary_to_hex(secret_text)
        if len(secret_key) != 4:
            secret_key = self.binary_to_hex(secret_key)
        # 获取第一轮和第二轮的拓展密钥
        keys = self.key_extend(secret_key)
        # 密文文轮密钥加
        temp = self.key_xor(keys[1], secret_text)
        # 第一轮
        temp = self.move_row(temp)
        temp = self.replace_res_inv(temp)
        temp = self.key_xor(keys[0], self.change_cov_to_str(temp))
        temp = self.col_mix_inv(temp)
        # 第二轮
        temp = self.move_row(temp)
        temp = self.replace_res_inv(temp)
        temp = self.key_xor(secret_key, self.change_cov_to_str(temp))
        plain_text = self.change_16to2(self.change_cov_to_str(temp))
        return plain_text

    # 切割函数
    def cut(self, bit_list):
        res = []
        for i in range(len(bit_list) // 8):
            res.append(bit_list[i * 8:i * 8 + 8])
        return res

    # 将字符串转变为二进制字符串
    def string_to_binary(self, s):
        return ''.join(format(ord(c), '08b') for c in s)

    # 字符串的加密函数
    def str_encrypt(self, plain_text, secret_key):
        if len(secret_key) != 4:
            secret_key = self.binary_to_hex(secret_key)
        str_01_list = self.string_to_binary(plain_text)
        str_01_list = self.cut(str_01_list)
        c_list_2 = []
        for i in range(len(str_01_list) // 2):
            str_temp_2 = str_01_list[i * 2] + str_01_list[i * 2 + 1]
            # 将组合好的二进制字符串变成十六进制字符串
            str_temp_16 = self.binary_to_hex(str_temp_2)
            # 调用加密函数
            res_temp_2 = self.encrypt(str_temp_16, secret_key)
            c_list_2.append(res_temp_2)
        # 将二进制字符串列表变为字母
        res = self.str_to_word(c_list_2)
        return res

    # 字符串的解密函数
    def str_decrypt(self, secret_text, secret_key):
        if len(secret_key) != 4:
            secret_key = self.binary_to_hex(secret_key)
        str_01_list = self.string_to_binary(secret_text)
        str_01_list = self.cut(str_01_list)
        c_list_2 = []
        for i in range(len(str_01_list) // 2):
            str_temp_2 = str_01_list[i * 2] + str_01_list[i * 2 + 1]
            # 将组合好的二进制字符串变成十六进制字符串
            str_temp_16 = self.binary_to_hex(str_temp_2)
            # 调用加密函数
            res_temp_2 = self.decrypt(str_temp_16, secret_key)
            c_list_2.append(res_temp_2)
        # 将二进制字符串列表变为字母
        res = self.str_to_word(c_list_2)
        return res

    # 暴力破解
    def brute_force(self, p, c):
        start_time = time.time()  # 获取当前时间
        for i in range(0, 65536):
            binary_str = bin(i)[2:].zfill(16)  # 生成密钥
            binary_str = self.binary_to_hex(binary_str)  # 生成16进制密钥
            ans = self.decrypt(c, binary_str)
            if ans == p:
                end_time = time.time()
                execution_time = end_time - start_time  # 计算两个时间点之间的差异
                return self.change_16to2(binary_str), str(execution_time * 1000)

    # 字符串暴力破解
    def str_brute_force(self, p, c):
        start_time = time.time()  # 获取当前时间
        for i in range(0, 65536):
            binary_str = bin(i)[2:].zfill(16)  # 生成密钥
            binary_str = self.binary_to_hex(binary_str)  # 生成16进制密钥
            ans = self.str_decrypt(c, binary_str)
            if ans == p:
                end_time = time.time()
                execution_time = end_time - start_time  # 计算两个时间点之间的差异
                return self.change_16to2(binary_str), str(execution_time * 1000)

    # 二进制的双重加密
    def double_encrypt(self, p, key):
        key1 = key[:16]
        key2 = key[16:]
        temp_c1 = self.encrypt(p, key1)
        res = self.encrypt(temp_c1, key2)
        return res

    # 二进制字符串双重解密
    def double_decrypt(self, c, key):
        key1 = key[:16]
        key2 = key[16:]
        temp_p1 = self.decrypt(c, key2)
        res = self.decrypt(temp_p1, key1)
        return res

    # 字符串双重加密
    def double_str_encrypt(self, p, key):
        key1 = key[:16]
        key2 = key[16:]
        temp_c1 = self.str_encrypt(p, key1)
        res = self.str_encrypt(temp_c1, key2)
        return res

    # 字符串的双重解密
    def double_str_decrypt(self, c, key):
        key1 = key[:16]
        key2 = key[16:]
        temp_p1 = self.str_decrypt(c, key2)
        res = self.str_decrypt(temp_p1, key1)
        return res

    # 中间相遇攻击
    def mid_attack(self, p, c):
        c_list = []
        for i in range(0, 65536):
            binary_str_k1 = bin(i)[2:].zfill(16)  # 生成密钥
            binary_str_k1 = self.binary_to_hex(binary_str_k1)  # 生成16进制密钥
            c_list.append(self.encrypt(p, binary_str_k1))
        res = []
        count = 0
        for i in range(0, 65536):
            binary_str_k2 = bin(i)[2:].zfill(16)  # 生成密钥
            binary_str_k2 = self.binary_to_hex(binary_str_k2)  # 生成16进制密钥
            temp_p = self.decrypt(c, binary_str_k2)
            for i in range(len(c_list)):
                if c_list[i] == temp_p:
                    count += 1
                    k1 = bin(i)[2:].zfill(16)
                    k2 = self.change_16to2(binary_str_k2)
                    res.append(k1 + k2)
        return res, count

    # 字符串的中间相遇攻击
    def mid_str_attack(self, p, c):
        c_list = []
        for i in range(0, 65536):
            binary_str_k1 = bin(i)[2:].zfill(16)  # 生成密钥
            binary_str_k1 = self.binary_to_hex(binary_str_k1)  # 生成16进制密钥
            c_list.append(self.str_encrypt(p, binary_str_k1))
        res = []
        count = 0
        for i in range(0, 65536):
            binary_str_k2 = bin(i)[2:].zfill(16)  # 生成密钥
            binary_str_k2 = self.binary_to_hex(binary_str_k2)  # 生成16进制密钥
            temp_p = self.str_decrypt(c, binary_str_k2)
            for i in range(len(c_list)):
                if c_list[i] == temp_p:
                    count += 1
                    k1 = bin(i)[2:].zfill(16)
                    k2 = self.change_16to2(binary_str_k2)
                    res.append(k1 + k2)
        return res, count

    # 三重加密
    def triple_encrypt(self, p, key):
        key1 = key[:16]
        key2 = key[16:32]
        key3 = key[32:]
        temp_c1 = self.encrypt(p, key1)
        temp_c2 = self.encrypt(temp_c1, key2)
        res = self.encrypt(temp_c2, key3)
        return res

    # 三重解密
    def triple_decrypt(self, c, key):
        key1 = key[: 16]
        key2 = key[16: 32]
        key3 = key[32:]
        temp_p1 = self.decrypt(c, key3)
        temp_p2 = self.decrypt(temp_p1, key2)
        res = self.decrypt(temp_p2, key1)
        return res

    # 字符串的三重加密
    def triple_str_encrypt(self, p, key):
        key1 = key[:16]
        key2 = key[16:32]
        key3 = key[32:]
        temp_c1 = self.str_encrypt(p, key1)
        temp_c2 = self.str_encrypt(temp_c1, key2)
        res = self.str_encrypt(temp_c2, key3)
        return res

    # 字符串三重解密
    def triple_str_decrypt(self, c, key):
        key1 = key[: 16]
        key2 = key[16: 32]
        key3 = key[32:]
        temp_p1 = self.str_decrypt(c, key3)
        temp_p2 = self.str_decrypt(temp_p1, key2)
        res = self.str_decrypt(temp_p2, key1)
        return res

    # 工作模式加密
    def CBC_encrypt(self, p, key, init_iv):
        if init_iv == '请在此输入初始向量':
            init_iv = self.create_key()
        else:
            init_iv = init_iv
        plains = []
        secrets = []
        i = 0
        while i < len(p):
            plains.append(p[i:i + 16])
            i += 16
        for i in range(len(plains)):
            if i == 0:
                temp = int(plains[i], 2) ^ int(init_iv, 2)
                secret = self.encrypt(bin(temp)[2:].zfill(16), key)
            else:
                temp = int(plains[i], 2) ^ int(secrets[i - 1], 2)
                secret = self.encrypt(bin(temp)[2:].zfill(16), key)
            secrets.append(secret)
        secret = ''
        for s in secrets:
            secret = secret + str(s)
        return secret, init_iv

    # 字符串工作模式加密
    def CBC_str_encrypt(self, p, key, init_iv):
        if init_iv == '请在此输入初始向量':
            init_iv = self.create_key()
        else:
            init_iv = init_iv
        p = self.string_to_binary(p)
        plains = []
        secrets = []
        i = 0
        while i < len(p):
            plains.append(p[i:i + 16])
            i += 16
        for i in range(len(plains)):
            if i == 0:
                temp = int(plains[i], 2) ^ int(init_iv, 2)
                secret = self.encrypt(bin(temp)[2:].zfill(16), key)
            else:
                temp = int(plains[i], 2) ^ int(secrets[i - 1], 2)
                secret = self.encrypt(bin(temp)[2:].zfill(16), key)
            secrets.append(secret)
        secret = ''
        for s in secrets:
            secret += str(s)
        secret = ''.join(chr(int(secret[i:i + 8], 2)) for i in range(0, len(secret), 8))
        return secret, init_iv

    # 工作模式解密
    def CBC_decrypt(self, c, key, init_iv):
        secrets = []
        plains = []
        i = 0
        while i < len(c):
            secrets.append(c[i:i + 16])
            i += 16
        secrets = secrets[::-1]
        for i in range(len(secrets)):
            if i == len(secrets) - 1:
                temp = self.decrypt(secrets[i], key)
                plain = bin(int(temp, 2) ^ int(init_iv, 2))[2:].zfill(16)
            else:
                temp = self.decrypt(secrets[i], key)
                plain = bin(int(temp, 2) ^ int(secrets[i + 1], 2))[2:].zfill(16)
            plains.append(plain)
        plains = plains[::-1]
        plain = ''
        for p in plains:
            plain += str(p)
        return plain

    # 工作模式字符串解密
    def CBC_str_decrypt(self, c, key, init_iv):
        c = self.string_to_binary(c)
        secrets = []
        plains = []
        i = 0
        while i < len(c):
            secrets.append(c[i:i + 16])
            i += 16
        secrets = secrets[::-1]
        for i in range(len(secrets)):
            if i == len(secrets) - 1:
                temp = self.decrypt(secrets[i], key)
                plain = bin(int(temp, 2) ^ int(init_iv, 2))[2:].zfill(16)
            else:
                temp = self.decrypt(secrets[i], key)
                plain = bin(int(temp, 2) ^ int(secrets[i + 1], 2))[2:].zfill(16)
            plains.append(plain)
        plains = plains[::-1]
        plain = ''
        for p in plains:
            plain += str(p)
        plain = ''.join(chr(int(plain[i:i + 8], 2)) for i in range(0, len(plain), 8))
        return plain

    # 生成16位随机密钥
    def create_key(self) -> str:
        str_key = ""
        for i in range(16):
            key = random.randint(0, 1)
            str_key += str(key)
        return str(str_key)

    def is_chinese(self, s):
        result = chardet.detect(s.encode())
        if result['encoding'] == 'utf-8' and any(ord(c) > 127 for c in s):
            return True
        else:
            return False


if __name__ == '__main__':
    db = S_AES()
    key = '55555555'
    key = db.change_16to2(key)
    print(key)
    p = 'ro'
    c = db.double_str_encrypt(p, key)
    print(c)
    p = '1234'
    c = db.double_encrypt(p, key)
    print(c)
    # 0111111110110001
    # 01101111001011010000111001011111
import tkinter as tk
import tkinter.messagebox
from tkinter import *
import S_AES_fun
import ttkbootstrap as ttk

# 窗口大小
page_size = '800x500+900+450'


# 主页面
class MainPage(object):
    # 初始化页面
    def __init__(self, master_page):
        self.page = None
        self.root = master_page
        self.root.geometry(page_size)
        self.init_page()

    def init_page(self):
        self.page = tk.Frame(self.root)
        self.page.pack(fill='both', ipadx=15, ipady=10, expand=True)

        '''
        '具体布局
        '''
        # 标题
        title_label = tk.Label(self.page, text='请选择您想要进行的操作', height=3, width=200, bg='white',
                               font=('Arial', 14))
        title_label.pack()

        # 设计按钮的样式，大小和位置
        # 跳转密钥破解
        to_secret_button = ttk.Button(self.page, text='    获取随机密钥    ', style='raised',
                                      command=self.to_get_secret)
        to_secret_button.pack(padx=5, ipady=10, pady=10, anchor='center')
        # 跳转加密
        to_encrypt_button = ttk.Button(self.page, text='    加密    ', style='raised', command=self.to_encrypt)
        to_encrypt_button.pack(padx=5, ipady=10, pady=10, anchor='center')
        # 跳转解密
        to_decrypt_button = ttk.Button(self.page, text='    解密    ', style='raised', command=self.to_decrypt)
        to_decrypt_button.pack(padx=5, ipady=10, pady=10, anchor='center')
        # 跳转密钥破解
        to_crack_button = ttk.Button(self.page, text='    密钥破解    ', style='raised', command=self.to_crack_key)
        to_crack_button.pack(padx=5, ipady=10, pady=10, anchor='center')
        # 跳转密码分组链模式
        to_crack_button = ttk.Button(self.page, text='    密码分组链模式    ', style='raised', command=self.to_CBC)
        to_crack_button.pack(padx=5, ipady=10, pady=10, anchor='center')

    # 跳转
    def to_get_secret(self):
        self.page.destroy()
        GetSecret(self.root)

    def to_encrypt(self):
        self.page.destroy()
        Encrypt(self.root)

    def to_decrypt(self):
        self.page.destroy()
        Decrypt(self.root)

    def to_crack_key(self):
        self.page.destroy()
        CrackKey(self.root)

    def to_CBC(self):
        self.page.destroy()
        CBC(self.root)


# 获取密钥页面
class GetSecret(object):
    # 初始化页面
    def __init__(self, master_page):
        self.page = None
        self.root = master_page
        self.root.geometry(page_size)
        self.init_page()

    def init_page(self):
        self.page = tk.Frame(self.root)
        self.page.pack(fill='both', ipadx=15, ipady=10, expand=True)

        '''
        '功能实现
        '''

        def get_secret():
            key = S_AES_fun.S_AES().create_key()
            secret_show.delete(0.0, tk.END)
            secret_show.insert('insert', key)

        '''
        '具体布局
        '''
        # 标题
        title_label = tk.Label(self.page, text='获取随机密钥', height=3, width=200, bg='white',
                               font=('Arial', 14))
        title_label.pack()

        # 密钥显示框
        secret_show = Text(self.page, height=1, width=20)
        secret_show.pack(pady=50, anchor='center')

        # 密钥获取按钮
        get_secret_button = ttk.Button(self.page, text='获取密钥', style='raised',
                                       command=get_secret)
        get_secret_button.pack(padx=100, ipady=100, pady=10)
        get_secret_button.place(x=250, y=300)

        # 返回按钮
        back_button = ttk.Button(self.page, text='返回', style='raised',
                                 command=self.to_back)
        back_button.pack(padx=100, ipady=100, pady=10)
        back_button.place(x=450, y=300)

    # 跳转
    def to_back(self):
        self.page.destroy()
        MainPage(self.root)


# 加密页面
class Encrypt(object):
    # 初始化页面
    def __init__(self, master_page):
        self.page = None
        self.root = master_page
        self.root.geometry(page_size)
        self.plain_text = ttk.StringVar()
        self.secret_key = ttk.StringVar()
        self.selected_default = ttk.IntVar()
        self.init_page()

    def init_page(self):
        self.page = tk.Frame(self.root)
        self.page.pack(fill='both', ipadx=15, ipady=10, expand=True)

        '''
        '功能实现
        '''

        # 实现输入框默认提示
        def key_fun(event):
            if self.secret_key.get() == '请在此输入密钥':
                secret_key_input.delete('0', 'end')
            if self.plain_text.get() == '':
                plain_text_input.insert('insert', '请在此输入明文')

        def plain_fun(event):
            if self.plain_text.get() == '请在此输入明文':
                plain_text_input.delete('0', 'end')
            if self.secret_key.get() == '':
                secret_key_input.insert('insert', '请在此输入密钥')

        # 实现加密操作
        def encrypt():
            secret_text_output.delete('0.0', 'end')  # 清空密文显示框
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 16:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            plain = self.plain_text.get()  # 从明文输入框获取明文
            if S_AES_fun.S_AES().is_chinese(plain):  # 处理二进制数据
                tk.messagebox.showerror('err', '明文含有汉字,请重新输入')
            else:
                if self.selected_default.get() == 1:
                    if len(plain) != 16:
                        tk.messagebox.showerror('err', '明文长度有误，请检查')
                        return -1
                    for i in range(len(plain)):
                        if plain[i] not in ['0', '1']:
                            tk.messagebox.showerror('err', '明文含有非二进制字符,请重新输入')
                            return -1
                    secret_text = S_AES_fun.S_AES().encrypt(plain, key)
                    secret_text_output.insert('insert', '密文：' + secret_text)
                if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                    if len(plain) % 2 == 1:
                        tk.messagebox.showerror('err', '明文应为偶数个字符')
                        return -1
                    secret_text = S_AES_fun.S_AES().str_encrypt(plain, key)
                    secret_text_output.insert('insert', '密文：' + secret_text)

        # 实现加密操作
        def double_encrypt():
            secret_text_output.delete('0.0', 'end')  # 清空密文显示框
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 32:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            plain = self.plain_text.get()  # 从明文输入框获取明文
            if S_AES_fun.S_AES().is_chinese(plain):  # 处理二进制数据
                tk.messagebox.showerror('err', '明文含有汉字,请重新输入')
            else:
                if self.selected_default.get() == 1:
                    if len(plain) != 16:
                        tk.messagebox.showerror('err', '明文长度有误，请检查')
                        return -1
                    for i in range(len(plain)):
                        if plain[i] not in ['0', '1']:
                            tk.messagebox.showerror('err', '明文含有非二进制字符,请重新输入')
                            return -1
                    secret_text = S_AES_fun.S_AES().double_encrypt(plain, key)
                    secret_text_output.insert('insert', '密文：' + secret_text)
                if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                    if len(plain) % 2 == 1:
                        tk.messagebox.showerror('err', '明文应为偶数个字符')
                        return -1
                    secret_text = S_AES_fun.S_AES().double_str_encrypt(plain, key)
                    secret_text_output.insert('insert', '密文：' + secret_text)

        # 实现加密操作
        def triple_encrypt():
            secret_text_output.delete('0.0', 'end')  # 清空密文显示框
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 48:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            plain = self.plain_text.get()  # 从明文输入框获取明文
            if S_AES_fun.S_AES().is_chinese(plain):  # 处理二进制数据
                tk.messagebox.showerror('err', '明文含有汉字,请重新输入')
            else:
                if self.selected_default.get() == 1:
                    if len(plain) != 16:
                        tk.messagebox.showerror('err', '明文长度有误，请检查')
                        return -1
                    for i in range(len(plain)):
                        if plain[i] not in ['0', '1']:
                            tk.messagebox.showerror('err', '明文含有非二进制字符,请重新输入')
                            return -1
                    secret_text = S_AES_fun.S_AES().triple_encrypt(plain, key)
                    secret_text_output.insert('insert', '密文：' + secret_text)
                if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                    if len(plain) % 2 == 1:
                        tk.messagebox.showerror('err', '明文应为偶数个字符')
                        return -1
                    secret_text = S_AES_fun.S_AES().triple_str_encrypt(plain, key)
                    secret_text_output.insert('insert', '密文：' + secret_text)

        '''
        '具体布局
        '''
        # 标题
        title_label = tk.Label(self.page, text='加密', height=3, width=200, bg='white',
                               font=('Arial', 14))
        title_label.pack()

        # 秘钥输入
        secret_key_input = ttk.Entry(self.page, textvariable=self.secret_key)
        secret_key_input.insert('insert', '请在此输入密钥')
        secret_key_input.bind('<Button-1>', key_fun)
        secret_key_input.pack(padx=100, ipady=100, pady=10)
        secret_key_input.place(relx=0.35, rely=0.2)

        # 明文输入
        plain_text_input = ttk.Entry(self.page, textvariable=self.plain_text)
        plain_text_input.insert('insert', '请在此输入明文')
        plain_text_input.bind('<Button-1>', plain_fun)
        plain_text_input.pack(padx=100, ipady=100, pady=10)
        plain_text_input.place(relx=0.35, rely=0.3)

        # 密文输出
        secret_text_output = ttk.Text(self.page, height=5, width=30)
        secret_text_output.place(relx=0.28, rely=0.4)
        secret_text_output.insert('insert', '密文：')
        secret_text_output['fg'] = 'grey'

        # 单次加密按钮
        encrypt_button = ttk.Button(self.page, text='单次加密', style='raised',
                                    command=encrypt)
        encrypt_button.pack(padx=100, ipady=100, pady=10)
        encrypt_button.place(relx=0.28, rely=0.7)

        # 双层加密按钮
        double_encrypt_button = ttk.Button(self.page, text='双重加密', style='raised',
                                           command=double_encrypt)
        double_encrypt_button.pack(padx=100, ipady=100, pady=10)
        double_encrypt_button.place(relx=0.43, rely=0.7)

        # 三重加密按钮
        triple_encrypt_button = ttk.Button(self.page, text='三重加密', style='raised',
                                           command=triple_encrypt)
        triple_encrypt_button.pack(padx=100, ipady=100, pady=10)
        triple_encrypt_button.place(relx=0.58, rely=0.7)
        # 模式选择
        options = ["明文为二进制数据", "明文为字符串（不含汉字）"]
        radiobutton_vars = []
        for option in options:
            radiobutton_vars.append(tk.StringVar())
        self.selected_default.set(2)
        for i in range(len(options)):
            radiobutton = tk.Radiobutton(self.page, text=options[i], value=i + 1, variable=self.selected_default)
            radiobutton.place(relx=0.72, rely=(0.3 + 0.06 * i))

        # 返回按钮
        back_button = ttk.Button(self.page, text='返回', style='raised',
                                 command=self.to_back)
        back_button.pack(padx=100, ipady=100, pady=10)
        back_button.place(relx=0.45, rely=0.8)

    # 跳转
    def to_back(self):
        self.page.destroy()
        MainPage(self.root)


# 解密页面
class Decrypt(object):
    # 初始化页面
    def __init__(self, master_page):
        self.page = None
        self.root = master_page
        self.root.geometry(page_size)
        self.secret_text = ttk.StringVar()
        self.secret_key = ttk.StringVar()
        self.selected_default = ttk.IntVar()
        self.init_page()

    def init_page(self):
        self.page = tk.Frame(self.root)
        self.page.pack(fill='both', ipadx=15, ipady=10, expand=True)

        '''
        '功能实现
        '''

        # 实现输入框默认提示
        def key_fun(event):
            if self.secret_key.get() == '请在此输入密钥':
                secret_key_input.delete('0', 'end')
            if self.secret_text.get() == '':
                secret_text_input.insert('insert', '请在此输入密文')

        def secret_fun(event):
            if self.secret_text.get() == '请在此输入密文':
                secret_text_input.delete('0', 'end')
            if self.secret_key.get() == '':
                secret_key_input.insert('insert', '请在此输入密钥')

        # 实现解密操作
        def decrypt():
            decrypt_text_output.delete('0.0', 'end')
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 16:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            secret_text = self.secret_text.get()  # 从密文输入框获取密文
            if self.selected_default.get() == 1:  # 处理二进制数据
                for i in range(len(secret_text)):
                    if secret_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '密文含有非二进制字符,请重新输入')
                        return -1
                if len(secret_text) != 16:
                    tk.messagebox.showerror('err', '密文长度有误，请检查')
                    return -1
                plain_text = S_AES_fun.S_AES().decrypt(secret_text, key)
                decrypt_text_output.insert('insert', '明文：' + plain_text)
            if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                if len(secret_text) % 2 == 1:
                    tk.messagebox.showerror('err', '密文应为偶数个字符')
                    return -1
                plain_text = S_AES_fun.S_AES().str_decrypt(secret_text, key)
                decrypt_text_output.insert('insert', '明文：' + plain_text)

        # 实现解密操作
        def double_decrypt():
            decrypt_text_output.delete('0.0', 'end')
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 32:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            secret_text = self.secret_text.get()  # 从密文输入框获取密文
            if self.selected_default.get() == 1:  # 处理二进制数据
                for i in range(len(secret_text)):
                    if secret_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '密文含有非二进制字符,请重新输入')
                        return -1
                if len(secret_text) != 16:
                    tk.messagebox.showerror('err', '密文长度有误，请检查')
                    return -1
                plain_text = S_AES_fun.S_AES().double_decrypt(secret_text, key)
                decrypt_text_output.insert('insert', '明文：' + plain_text)
            if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                if len(secret_text) % 2 == 1:
                    tk.messagebox.showerror('err', '密文应为偶数个字符')
                    return -1
                plain_text = S_AES_fun.S_AES().double_str_decrypt(secret_text, key)
                decrypt_text_output.insert('insert', '明文：' + plain_text)

        # 实现解密操作
        def triple_decrypt():
            decrypt_text_output.delete('0.0', 'end')
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 48:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            secret_text = self.secret_text.get()  # 从密文输入框获取密文
            if self.selected_default.get() == 1:  # 处理二进制数据
                for i in range(len(secret_text)):
                    if secret_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '密文含有非二进制字符,请重新输入')
                        return -1
                if len(secret_text) != 16:
                    tk.messagebox.showerror('err', '密文长度有误，请检查')
                    return -1
                plain_text = S_AES_fun.S_AES().triple_decrypt(secret_text, key)
                decrypt_text_output.insert('insert', '明文：' + plain_text)
            if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                if len(secret_text) % 2 == 1:
                    tk.messagebox.showerror('err', '密文应为偶数个字符')
                    return -1
                plain_text = S_AES_fun.S_AES().triple_str_decrypt(secret_text, key)
                decrypt_text_output.insert('insert', '明文：' + plain_text)

        '''
        '具体布局
        '''
        # 标题
        title_label = tk.Label(self.page, text='解密', height=3, width=200, bg='white',
                               font=('Arial', 14))
        title_label.pack()

        # 秘钥输入
        secret_key_input = ttk.Entry(self.page, textvariable=self.secret_key)
        secret_key_input.insert('insert', '请在此输入密钥')
        secret_key_input.bind('<Button-1>', key_fun)
        secret_key_input.pack(padx=100, ipady=100, pady=10)
        secret_key_input.place(relx=0.35, rely=0.2)

        # 密文输入
        secret_text_input = ttk.Entry(self.page, textvariable=self.secret_text)
        secret_text_input.insert('insert', '请在此输入密文')
        secret_text_input.bind('<Button-1>', secret_fun)
        secret_text_input.pack(padx=100, ipady=100, pady=10)
        secret_text_input.place(relx=0.35, rely=0.3)

        # 模式选择
        options = ["密文由二进制数据加密", "密文由字符串（不含汉字）加密"]
        radiobutton_vars = []
        for option in options:
            radiobutton_vars.append(tk.StringVar())
        self.selected_default.set(2)
        for i in range(len(options)):
            radiobutton = tk.Radiobutton(self.page, text=options[i], value=i + 1, variable=self.selected_default)
            radiobutton.place(relx=0.72, rely=(0.3 + 0.06 * i))

        # 解密后的明文输出
        decrypt_text_output = ttk.Text(self.page, height=5, width=30)
        decrypt_text_output.place(relx=0.28, rely=0.4)
        decrypt_text_output.insert('insert', '解密结果：')
        decrypt_text_output['fg'] = 'grey'

        # 单次解密按钮
        decrypt_button = ttk.Button(self.page, text='单次解密', style='raised',
                                    command=decrypt)
        decrypt_button.pack(padx=100, ipady=100, pady=10)
        decrypt_button.place(relx=0.28, rely=0.7)

        # 双重解密按钮
        double_decrypt_button = ttk.Button(self.page, text='双重解密', style='raised',
                                           command=double_decrypt)
        double_decrypt_button.pack(padx=100, ipady=100, pady=10)
        double_decrypt_button.place(relx=0.43, rely=0.7)

        # 三重解密按钮
        triple_decrypt_button = ttk.Button(self.page, text='三重解密', style='raised',
                                           command=triple_decrypt)
        triple_decrypt_button.pack(padx=100, ipady=100, pady=10)
        triple_decrypt_button.place(relx=0.58, rely=0.7)

        # 返回按钮
        back_button = ttk.Button(self.page, text='返回', style='raised',
                                 command=self.to_back)
        back_button.pack(padx=100, ipady=100, pady=10)
        back_button.place(relx=0.45, rely=0.8)

    # 跳转
    def to_back(self):
        self.page.destroy()
        MainPage(self.root)


# 密钥破解页面
class CrackKey(object):
    # 初始化页面
    def __init__(self, master_page):
        self.page = None
        self.root = master_page
        self.root.geometry(page_size)
        self.plain_text = ttk.StringVar()
        self.secret_text = ttk.StringVar()
        self.selected_default = ttk.IntVar()
        self.init_page()

    def init_page(self):
        self.page = tk.Frame(self.root)
        self.page.pack(fill='both', ipadx=15, ipady=10, expand=True)

        '''
        '功能实现
        '''

        # 实现输入框默认提示
        def plain_fun(event):
            if self.plain_text.get() == '请在此输入明文':
                plain_text_input.delete('0', 'end')
            if self.secret_text.get() == '':
                secret_text_input.insert('insert', '请在此输入密文')

        def secret_fun(event):
            if self.secret_text.get() == '请在此输入密文':
                secret_text_input.delete('0', 'end')
            if self.plain_text.get() == '':
                plain_text_input.insert('insert', '请在此输入明文')

        # 实现解密操作
        def decrypt():
            decrypt_text_output.delete('0.0', 'end')
            plain_text = self.plain_text.get()  # 从明文输入框获取明文
            secret_text = self.secret_text.get()  # 从密文输入框获取密文
            if self.selected_default.get() == 1:  # 处理二进制数据
                for i in range(len(secret_text)):
                    if secret_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '密文含有非二进制字符,请重新输入')
                        return -1
                for i in range(len(plain_text)):
                    if plain_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '明文含有非二进制字符,请重新输入')
                        return -1
                if len(plain_text) != 16:
                    tk.messagebox.showerror('err', '明文长度有误，请检查')
                    return -1
                if len(secret_text) != 16:
                    tk.messagebox.showerror('err', '密文长度有误，请检查')
                    return -1
                decrypted = S_AES_fun.S_AES().brute_force(plain_text, secret_text)
                if decrypted is None:
                    print("返回为空")
                else:
                    decrypt_text_output.insert('insert',
                                               '本次破解所用密钥为：' + decrypted[0] + '\n破解所用时间为：' +
                                               decrypted[1] + 'ms')
            if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                decrypted = S_AES_fun.S_AES().str_brute_force(plain_text, secret_text)
                if decrypted is None:
                    print("返回为空")
                else:
                    decrypt_text_output.insert('insert',
                                               '本次破解所用密钥为：' + decrypted[0] + '\n破解所用时间为：' +
                                               decrypted[1] + 'ms')

        # 实现中间相遇攻击
        def middle_encounter_attack():
            decrypt_text_output.delete('0.0', 'end')
            plain_text = self.plain_text.get()  # 从明文输入框获取明文
            secret_text = self.secret_text.get()  # 从密文输入框获取密文
            if self.selected_default.get() == 1:  # 处理二进制数据
                for i in range(len(secret_text)):
                    if secret_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '密文含有非二进制字符,请重新输入')
                        return -1
                for i in range(len(plain_text)):
                    if plain_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '明文含有非二进制字符,请重新输入')
                        return -1
                if len(plain_text) != 16:
                    tk.messagebox.showerror('err', '明文长度有误，请检查')
                    return -1
                if len(secret_text) != 16:
                    tk.messagebox.showerror('err', '密文长度有误，请检查')
                    return -1
                decrypted, count = S_AES_fun.S_AES().mid_attack(plain_text, secret_text)
                if decrypted is None:
                    print("返回为空")
                else:
                    decrypt_text_output.insert('insert',
                                               '符合条件的密钥数量为：' + str(count) + '\n第一个符合条件的密钥是：' +
                                               decrypted[0])
            if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                decrypted, count = S_AES_fun.S_AES().mid_str_attack(plain_text, secret_text)
                if decrypted is None:
                    print("返回为空")
                else:
                    decrypt_text_output.insert('insert',
                                               '符合条件的密钥数量为：' + str(count) + '\n第一个符合条件的密钥是：' +
                                               decrypted[0])

        '''
        '具体布局
        '''
        # 标题
        title_label = tk.Label(self.page, text='暴力破解', height=3, width=200, bg='white',
                               font=('Arial', 14))
        title_label.pack()

        # 密文输入
        secret_text_input = ttk.Entry(self.page, textvariable=self.secret_text)
        secret_text_input.insert('insert', '请在此输入密文')
        secret_text_input.bind('<Button-1>', secret_fun)
        secret_text_input.pack(padx=100, ipady=100, pady=10)
        secret_text_input.place(relx=0.35, rely=0.2)

        # 明文输入
        plain_text_input = ttk.Entry(self.page, textvariable=self.plain_text)
        plain_text_input.insert('insert', '请在此输入明文')
        plain_text_input.bind('<Button-1>', plain_fun)
        plain_text_input.pack(padx=100, ipady=100, pady=10)
        plain_text_input.place(relx=0.35, rely=0.3)

        # 模式选择
        options = ["明文为二进制数据", "明文为字符串（不含汉字）"]
        radiobutton_vars = []
        for option in options:
            radiobutton_vars.append(tk.StringVar())
        self.selected_default.set(2)
        for i in range(len(options)):
            radiobutton = tk.Radiobutton(self.page, text=options[i], value=i + 1, variable=self.selected_default)
            radiobutton.place(relx=0.72, rely=(0.3 + 0.06 * i))

        # 解密结果输出
        decrypt_text_output = ttk.Text(self.page, height=5, width=30)
        decrypt_text_output.place(relx=0.28, rely=0.4)
        decrypt_text_output.insert('insert', '解密结果：')
        decrypt_text_output['fg'] = 'grey'

        # 暴力破解按钮
        decrypt_button = ttk.Button(self.page, text='暴力破解', style='raised',
                                    command=decrypt)
        decrypt_button.pack(padx=100, ipady=100, pady=10)
        decrypt_button.place(relx=0.33, rely=0.7)

        # 中间相遇攻击按钮
        middle_button = ttk.Button(self.page, text='中间相遇攻击', style='raised',
                                   command=middle_encounter_attack)
        middle_button.pack(padx=100, ipady=100, pady=10)
        middle_button.place(relx=0.47, rely=0.7)

        # 返回按钮
        back_button = ttk.Button(self.page, text='返回', style='raised',
                                 command=self.to_back)
        back_button.pack(padx=100, ipady=100, pady=10)
        back_button.place(relx=0.45, rely=0.8)

    # 跳转
    def to_back(self):
        self.page.destroy()
        MainPage(self.root)


# CBC模式页面
class CBC(object):
    # 初始化页面
    def __init__(self, master_page):
        self.page = None
        self.root = master_page
        self.root.geometry(page_size)
        self.text = ttk.StringVar()
        self.init_iv = ttk.StringVar()
        self.secret_key = ttk.StringVar()
        self.selected_default = ttk.IntVar()
        self.init_page()

    def init_page(self):
        self.page = tk.Frame(self.root)
        self.page.pack(fill='both', ipadx=15, ipady=10, expand=True)

        '''
        '功能实现
        '''

        # 实现输入框默认提示
        def key_fun(event):
            if self.secret_key.get() == '请在此输入密钥':
                secret_key_input.delete('0', 'end')
            elif self.secret_key.get() == '':
                secret_key_input.insert('insert', '请在此输入密钥')

        # 实现输入框默认提示
        def text_fun(event):
            if self.text.get() == '请在此输入明文或密文':
                text_input.delete('0', 'end')
            elif self.text.get() == '':
                text_input.insert('insert', '请在此输入明文或密文')

        # 实现输入框默认提示
        def init_fun(event):
            if self.init_iv.get() == '请在此输入初始向量':
                init_input.delete('0', 'end')
            elif self.init_iv.get() == '':
                init_input.insert('insert', '请在此输入初始向量')

        # 实现CBC模式下的加密
        def CBC_encrypt():
            result_output.delete('0.0', 'end')  # 清空密文显示框
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 16:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            init_iv = self.init_iv.get()  # 从初始向量输入框获取初始向量
            if len(init_iv) != 16:
                tk.messagebox.showerror('err', '初始向量长度有误，请检查')
                return -1
            if not init_iv.isdigit():
                tk.messagebox.showerror('err', '初始向量含有非二进制字符，请检查')
                return -1
            plain = self.text.get()  # 从输入框获取明文
            if S_AES_fun.S_AES().is_chinese(plain):  # 处理二进制数据
                tk.messagebox.showerror('err', '明文含有汉字,请重新输入')
            else:
                if self.selected_default.get() == 1:
                    for i in range(len(plain)):
                        if plain[i] not in ['0', '1']:
                            tk.messagebox.showerror('err', '明文含有非二进制字符,请重新输入')
                            return -1
                    secret_text, init_iv = S_AES_fun.S_AES().CBC_encrypt(plain, key, init_iv)
                    result_output.insert('insert', '密文：' + secret_text + '\n初始向量：' + init_iv)
                if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                    if len(plain) % 2 == 1:
                        tk.messagebox.showerror('err', '明文应为偶数个字符')
                        return -1
                    secret_text, init_iv = S_AES_fun.S_AES().CBC_str_encrypt(plain, key, init_iv)
                    result_output.insert('insert', '密文：' + secret_text + '\n初始向量：' + init_iv)

        # 实现CBC模式下的解密
        def CBC_decrypt():
            result_output.delete('0.0', 'end')
            key = self.secret_key.get()  # 从密钥输入框获取密钥
            if len(key) != 16:
                tk.messagebox.showerror('err', '密钥长度有误，请检查')
                return -1
            if not key.isdigit():
                tk.messagebox.showerror('err', '密钥含有非二进制字符，请检查')
                return -1
            init_iv = self.init_iv.get()  # 从初始向量输入框获取初始向量
            if len(init_iv) != 16:
                tk.messagebox.showerror('err', '初始向量长度有误，请检查')
                return -1
            if not init_iv.isdigit():
                tk.messagebox.showerror('err', '初始向量含有非二进制字符，请检查')
                return -1
            secret_text = self.text.get()  # 从文本输入框获取密文
            if self.selected_default.get() == 1:  # 处理二进制数据
                for i in range(len(secret_text)):
                    if secret_text[i] not in ['0', '1']:
                        tk.messagebox.showerror('err', '密文含有非二进制字符,请重新输入')
                        return -1
                plain_text = S_AES_fun.S_AES().CBC_decrypt(secret_text, key, init_iv)
                result_output.insert('insert', '明文：' + plain_text)
            if self.selected_default.get() == 2:  # 处理ASCII字符串数据
                plain_text = S_AES_fun.S_AES().CBC_str_decrypt(secret_text, key, init_iv)
                result_output.insert('insert', '明文：' + plain_text)

        '''
        '具体布局
        '''
        # 标题
        title_label = tk.Label(self.page, text='密码分组链模式', height=3, width=200, bg='white',
                               font=('Arial', 14))
        title_label.pack()

        # 秘钥输入
        secret_key_input = ttk.Entry(self.page, textvariable=self.secret_key)
        secret_key_input.insert('insert', '请在此输入密钥')
        secret_key_input.bind('<FocusIn>', key_fun)
        secret_key_input.bind('<FocusOut>', key_fun)
        secret_key_input.pack(padx=100, ipady=100, pady=10)
        secret_key_input.place(relx=0.35, rely=0.2)

        # 文本输入
        text_input = ttk.Entry(self.page, textvariable=self.text)
        text_input.insert('insert', '请在此输入明文或密文')
        text_input.bind('<FocusIn>', text_fun)
        text_input.bind('<FocusOut>', text_fun)
        text_input.pack(padx=100, ipady=100, pady=10)
        text_input.place(relx=0.35, rely=0.3)

        # 初始向量输入
        init_input = ttk.Entry(self.page, textvariable=self.init_iv)
        init_input.insert('insert', '请在此输入初始向量')
        init_input.bind('<FocusIn>', init_fun)
        init_input.bind('<FocusOut>', init_fun)
        init_input.pack(padx=100, ipady=100, pady=10)
        init_input.place(relx=0.35, rely=0.4)

        # 模式选择
        options = ["明文为二进制数据", "明文为字符串（不含汉字）"]
        radiobutton_vars = []
        for option in options:
            radiobutton_vars.append(tk.StringVar())
        self.selected_default.set(2)
        for i in range(len(options)):
            radiobutton = tk.Radiobutton(self.page, text=options[i], value=i + 1, variable=self.selected_default)
            radiobutton.place(relx=0.72, rely=(0.3 + 0.06 * i))

        # 结果输出
        result_output = ttk.Text(self.page, height=4, width=30)
        result_output.place(relx=0.28, rely=0.5)
        result_output.insert('insert', '密文：')
        result_output['fg'] = 'grey'

        # 加密按钮
        encrypt_button = ttk.Button(self.page, text='加密', style='raised',
                                    command=CBC_encrypt)
        encrypt_button.pack(padx=100, ipady=100, pady=10)
        encrypt_button.place(relx=0.4, rely=0.75)

        # 解密按钮
        decrypt_button = ttk.Button(self.page, text='解密', style='raised',
                                    command=CBC_decrypt)
        decrypt_button.pack(padx=100, ipady=100, pady=10)
        decrypt_button.place(relx=0.5, rely=0.75)

        # 返回按钮
        back_button = ttk.Button(self.page, text='返回', style='raised',
                                 command=self.to_back)
        back_button.pack(padx=100, ipady=100, pady=10)
        back_button.place(relx=0.45, rely=0.85)

    # 跳转
    def to_back(self):
        self.page.destroy()
        MainPage(self.root)


page = ttk.Window()
page.geometry('600x400+900+450')
# 窗口名称
page.title('S-AES加密解密系统')
# 禁止调节窗口大小
page.resizable(False, False)
MainPage(page)
page.mainloop()
# 0101010101010101
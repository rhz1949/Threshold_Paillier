import time
import gmpy2
import math
import random

user_num = 10  ####参与解密的人数
thre = int(user_num/2) ##解密的阈值
deta = math.factorial(user_num)

####以下两个函数不用管，是生成密钥时keygen()调用的
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m



def get_prime(rs):
    p = gmpy2.mpz_urandomb(rs, 256)
    while not (gmpy2.is_prime(p) and gmpy2.is_prime(2 * p + 1)):
        p = p + 1
    return p, (2*p + 1)
def LL(x, n):
    return (x - 1) // n

def keygen():
    rs = gmpy2.random_state(int(time.time()))
    _p, p = get_prime(rs)
    _q, q = get_prime(rs)

    m = _p * _q
    n = p * q
    lmd = (p - 1) * (q - 1)
    g = n + 1

    pk = [n, g]
    sk = lmd

    d = m * modinv(m, n)

    return pk, sk, m, d

def encipher(plaintext, pk):
    m = plaintext
    n, g = pk
    r = random.randint(1, n ** 2)
    c = gmpy2.powmod(g, int(m), n ** 2) * gmpy2.powmod(r, int(n), n ** 2) % (n ** 2)
    return c


####生成部分私钥
def share_private_key(s, t, pk, d, m):  ###一共s个人，阈值为t
    coffe = []
    n = pk[0]
    nm = n*m
    coffe.append(d)
    for i in range(t-1):
        coffe.append(random.randint(0, nm-1))

    share_pri = []
    for user in range(1, s+1):
        total = 0
        for j in range(t):
            total = (total + pow(user, j) * coffe[j])
        share_pri.append(total % nm)

    return share_pri


###部分解密，i_share_pri代表用户i的部分私钥
def partial_decryption(i_share_pri, ciphertext, n):
    pa_de = gmpy2.powmod(int(ciphertext), int(2 * deta * i_share_pri), n ** 2) % (n ** 2)
    return pa_de

####联合解密，arr_pa_de是解密出来的部分密文的数组
def combining(arr_pa_de, pk):
    length = thre
    lam = []
    c = 1
    n, g = pk

    for i in range(1, length+1):
        temp_com = 1
        temp_com1 = 1
        for j in range(1, length+1):
            if(i != j):
                temp_com = temp_com * (-j)
                temp_com1 = temp_com1 * (i - j)
        lam.append(temp_com // temp_com1)

    c = 1
    for i in range(length):
        if lam[i] > 0:
            temp = gmpy2.powmod(int(arr_pa_de[i]), int(lam[i] * 2 * deta), n ** 2)
           # print('c_[',i,'] = ', temp, '\n')
            c = c * temp % (n ** 2)
        elif lam[i] == 0:
            continue
        elif lam[i] < 0:
            temp = gmpy2.powmod(int(arr_pa_de[i]), int(-lam[i] * 2*deta), n ** 2)
          #print('c_[',i,'] = ', temp, '\n')
            c = c * gmpy2.invert(temp, n ** 2) % (n ** 2)

    c = c % (n ** 2)
    u = gmpy2.invert(LL(gmpy2.powmod(g, int(4 * (deta ** 2)), n ** 2), n), n) % (n ** 2)
    c_u = LL(c, n)
    plaintext = c_u * u % n

    return plaintext


##用于单个解密的函数
def decipher(c, pk, sk):
    [n, g] = pk
    lmd = sk
    u = gmpy2.invert(LL(gmpy2.powmod(g, lmd, n ** 2), n), n) % n
    m = LL(gmpy2.powmod(c, lmd, n ** 2), n) * u % n
    plaintext = m
    return plaintext


#### sk是用于单个用户解密时的私钥，d是阈值解密的私钥
#####keygen生成公钥，d，sk等参数
pk, sk, m, d = keygen()

####生成部分私钥
share_key = share_private_key(user_num, thre, pk, d, m)

def test():
    plaintext = 11
    c_text = encipher(plaintext, pk)  ###加密

    pa_c = []

    #####部分解密
    for user in range(user_num):
        pa_c.append(partial_decryption(share_key[user], c_text, pk[0]))


    p1_1 = combining(pa_c, pk)  ###联合解密，不需要d以及sk
    p1_2 = decipher(c_text, pk, sk)  ####单独解密，用到了私钥sk

    print('联合解密解密出来的密文是：', p1_1)
    print('单独解密解密出来的密文是：', p1_2)


test()
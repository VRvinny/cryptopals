import base64
import binascii
import string
import codecs
import freqAnalysis
from itertools import cycle


def hextob64(string):
    return (base64.b64encode(binascii.unhexlify(string)).decode('ascii'))
# add try catch methods for non b64 chars


def b64tohex(string):
    # only works in python2
    # print(base64.b64decode(string).decode('ascii').encode("hex"))
    return binascii.hexlify(base64.b64decode(string).decode('ascii'))


def xor(first, second):
    # takes string arguments in hex , returns string value also in hex
    b1 = bytearray.fromhex(first)
    b2 = bytearray.fromhex(second)

    #ans = [a^b for (a,b) in zip(b1, b2)]
    #return  "".join( str(hex(a))[2:] for a in ans )
    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b


def xordec(enc):
    # takes ascii encoded in hex
    length = len(enc)//2
    for char in string.ascii_letters:

        padding = (hex(ord(char))[2:] *length).strip()
        strdec = xor(enc, padding).decode("ascii")




        score = validate(strdec)
        if score == 1:
            if freqAnalysis.englishFreqMatchScore(strdec)>4:
                print(char, strdec)

    #print(enc)





# calc 6b47474341464f08656b0f5b084441434d08490858475d464c08474e084a494b4746
# asda 6b47474341464f8656bf5b84441434d849858475d464c8474e84a494b4746


def validate(strdec):
    for c in strdec:
        if (ord(c) < 32):
            #contains unprintable characters
            return 0

    #contains printable characters
    return 1



def chal1():
    str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    print(hextob64(str))


def chal2():
    str1 = "1c0111001f010100061a024b53535009181c"
    str2 = "686974207468652062756c6c277320657965"
    print(xor(str1, str2))


def chal3():
 str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
 xordec(str)


def chal4():
    stringgg = "0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032"
    '''
    file = open("file.txt", "r")
    for l in file:
        print(l.strip())
        xordec(l.strip())
        '''
    for i in range(len(stringgg)//2 + 1):
        print(stringgg[:(2*i)])
        xordec(stringgg[:(2*i)] )
    #xordec("0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032")



def main():
    chal4()


if __name__ == '__main__':
    main()

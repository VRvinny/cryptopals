import base64
import binascii
import string
import codecs
import freqAnalysis
from itertools import cycle
#https://github.com/ricpacca/cryptopals
#ETAOIN SHRDLU
freqValues = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182,
    #"$": -0.1, "}" : -0.1, "%": -0.1, "^":-0.1, "*":0.1
    }


def hextob64(string):
    # convert hex to binary to b64
    return (base64.b64encode(binascii.unhexlify(string)))

def xor(str1, str2):
    if len(str1) != len(str2):
        return
    return hex( int(str1, 16)^ int(str2, 16))[2:]


def singlexor(first, second):
    b1 = bytearray.fromhex(first)
    b2 = bytearray.fromhex(second)

    b = bytearray(len(b1))
    for i in range(len(b1)):
        b[i] = b1[i] ^ b2[i]
    return b


def xordec(str1):
    for char in string.printable:
        if char in string.whitespace:
            continue
        #works
        padding = hex(ord(char))[2:] * (len(str1) // 2)
        xorByteString = singlexor(padding, str1)
        hexstring = binascii.hexlify(xorByteString).decode()

        #asciistring = codecs.decode(hexstring, "hex").decode()
        if validate(xorByteString) == 1:
            score = scoreText(xorByteString)
            if score > 1.0:
                print(char, score, codecs.decode(hexstring, "hex").decode())



def scoreText(strdec):
    score = 0
    for char in strdec:
        if chr(char).lower() in freqValues:
            score += freqValues.get(chr(char).lower(), 0)

    return score


def validate(strdec):
    # \n at the end
    for i in strdec[:-1]:
        if i < 32 or i > 127:
            return 0
    return 1


def chal1():
    str1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    #convert string to byte format
    b1 = str.encode(str1)
    print(hextob64(b1))


def chal2():
    str1 = "1c0111001f010100061a024b53535009181c"
    str2 = "686974207468652062756c6c277320657965"
    print(xor(str1, str2))
    #print(str.encode(xor(str1,str2)))


def chal3():
    str1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    #436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e
    #Cooking MC's like a pound of bacon

    xordec(str1)


def chal4():

# right one 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
# plaintext 4e6f77207468617420746865207061727479206973206a756d70696e670a
#           Now that the party is jumping
    file = open("file.txt", "r")
    for l in file:
        xordec(l.strip())


def main():
    chal4()


    '''
    # convert from hex string  to byte
    byteversion =  bytes.fromhex(str1)
    # convert from byte hex encoded to byte hex
    bytehex = binascii.hexlify(byteversion)

    asdf = bytes.fromhex("436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e")
    # convert from byte hex to hex string
    hexstring = binascii.hexlify(asdf)
    # convert byte hex string to ascii
    asciistring = asdf.decode()
    print(hexstring)
    '''


if __name__ == '__main__':
    main()

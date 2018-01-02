# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.
from Crypto import Random
from Crypto.Cipher import AES
import os
import binascii
from Crypto.Util import Counter
import Crypto.Util.Counter
from binascii import hexlify
__author__ = "mdv"
__date__ = "$Apr 29, 2016 11:41:02 PM$"

if __name__ == "__main__":
################################################################################
    print ("Trabalho 3 - AES - PyCrypto")
print ("Autor - Matheus Duarte Vasconcelos")
print ("DISCIPLINA DE CRIPTOGRAFIA\n")
################################################################################
print ("TASK 1 => CBC Mode - Decrypt - OK")
CBCkey = binascii.unhexlify('140b41b22a29beb4061bda66b6747e14')
cipherText1 = binascii.unhexlify('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
iv = binascii.unhexlify('4ca00ff4c898d61e1edbf1800618fb28')
cipher = AES.new(CBCkey, AES.MODE_CBC, iv)
print ("Cipher text 1: ", binascii.hexlify(cipherText1))
decryptor = cipher.decrypt(cipherText1)
print ("Plain text 1 ", decryptor[16:-8])#print sem pad e chave
print ("--------------------------------------------------------------------")
print ("\n")
################################################################################
print ("TASK 2 => CBC Mode - Decrypt - OK")
CBCkey2 = binascii.unhexlify('140b41b22a29beb4061bda66b6747e14')
CBCCiphertext2 = binascii.unhexlify('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
iv2 = binascii.unhexlify('5b68629feb8606f9a6667670b75b38a5')
cipher2 = AES.new(CBCkey2, AES.MODE_CBC, iv2)
print ("Cipher text 2: ", binascii.hexlify(CBCCiphertext2))
decryptor2 = cipher2.decrypt(CBCCiphertext2)
print ("Plain text 2:  ", decryptor2[16:-16])
print ("--------------------------------------------------------------------")
print ("--------------------------------------------------------------------")
################################################################################
print ("\n\nTASK 3 => CTR Mode - Decrypt - OK")
CTRkey = ('36f18357be4dbd77f050515c73fcf9f2')
CTRkey = CTRkey.decode("hex")
CTRCiphertext_iv3 = ( '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
CTRCiphertext_iv3 = CTRCiphertext_iv3.decode("hex")#texto cifrado + IV
block_size = AES.block_size
#print ("Tamanho do bloco",block_size)
iv3 = (CTRCiphertext_iv3[:block_size])#primeiros bytes sao o IV
cipherText3 = CTRCiphertext_iv3[block_size:]#separa texto cifrado do IV
print long(iv3.encode("hex"), block_size)#mostrar IV
ctr3 = Counter.new(128, initial_value = long(iv3.encode("hex"), block_size))
cipher3 = AES.new(CTRkey, AES.MODE_CTR, counter=ctr3)
print ("Plain text 3:",cipher3.decrypt(cipherText3))
print ("--------------------------------------------------------------------")
################################################################################
print ("\n\nTASK 4 => CTR Mode - Decrypt - OK")
CTRkey4 = ('36f18357be4dbd77f050515c73fcf9f2')
CTRCiphertext4_iv4 = ('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
CTRkey4 = CTRkey4.decode("hex")
CTRCiphertext4_iv4 = CTRCiphertext4_iv4.decode("hex")
block_size = AES.block_size
#print ("Tamanho do bloco",block_size) 
iv4 = CTRCiphertext4_iv4[:block_size]
print long(iv4.encode("hex"), block_size)#mostrar IV
cipherText4 = CTRCiphertext4_iv4[block_size:] 
ctr4 = Counter.new(128, initial_value = long(iv4.encode("hex"), block_size))
cipher4 = AES.new(CTRkey4, AES.MODE_CTR, counter=ctr4)
print ("Plaintext  4: ", cipher4.decrypt(cipherText4))
print ("--------------------------------------------------------------------")
print ("--------------------------------------------------------------------")
################################################################################
#Task 5 - ctr encrypt
print ("\n\nTASK 5 => CTR Mode - Encrypt - OK")
plaintxtTask5 = ('5468697320697320612073656e74656e636520746f20626520656e63727970746564207573696e672041455320616e6420435452206d6f64652e').decode("hex")
keyTask5 = ('36f18357be4dbd77f050515c73fcf9f2').decode("hex")
counter = os.urandom(16)
#counter = ('443fb7623534883df6156fa4d43754ce').decode("hex")#teste incializacao counter
ctr = Counter.new(128, initial_value = long(counter.encode("hex"), 16))
encrypto = AES.new(keyTask5, AES.MODE_CTR, counter=ctr)
encrypted = encrypto.encrypt(plaintxtTask5)
print ("CipherTxt5:        ", encrypted.encode("hex"))
#coloca IV counter no inicio do texto cifrado
cipher_iv = counter.encode("hex") + encrypted.encode("hex")
print ("Cipher+IV Counter: ", cipher_iv)
print ("--------------------------------------------------------------------")
print ("--------------------------------------------------------------------")
################################################################################
print ("\n\nTASK 6 => CBC Mode - Encrypt - OK")
BLOCK_SIZE = 16
PADDING = '{' #0x7b
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING #fonte: https://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/
keyTask6 =      binascii.unhexlify('140b41b22a29beb4061bda66b6747e14')
plaintxtTask6 = binascii.unhexlify('4e657874205468757273646179206f6e65206f66207468652062657374207465616d7320696e2074686520776f726c642077696c6c2066616365206120626967206368616c6c656e676520696e20746865204c696265727461646f72657320646120416d6572696361204368616d70696f6e736869702e')
iv = os.urandom(16)
iv6 = binascii.unhexlify(iv.encode('hex'))
print ("IV6:         ", iv6.encode('hex'))
EncodeAES = lambda c, s: (c.encrypt(pad(s)))
cipher = AES.new(keyTask6, AES.MODE_CBC, iv6)
encoded = EncodeAES(cipher, plaintxtTask6)
print 'Cipher text:', encoded.encode('hex')
##utilizado para teste - decrypt a mensagem anterior - tambem testado em http://aes.online-domain-tools.com/
#print "\ndecrypt text"
#decrypt = binascii.unhexlify(encoded.encode('hex'))
#cipherDcr = AES.new(keyTask6, AES.MODE_CBC, iv6)
#decryptor = cipherDcr.decrypt(decrypt)
#print ("Plain text 1 ", decryptor[14:-8])#print sem pad
################################################################################
print ("--------------------------------------------------------------------")
print ("--------------------------------------------------------------------")
quit()


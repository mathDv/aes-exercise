# aes-exercise
Python aes exercise

Cryptography - AES and operation modes
Prof. Avelino Zorzo - PPGCC/Facin/PUCRS
Exercise based on Introduction to Cryptography, Stanford University, Dan Boneh 

In this exercise you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR). In all cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext. For CBC encryption PKCS5 padding scheme was used.
Implement both encryption and decryption. In the following questions you are given an AES key and a ciphertext/plaintext (all are hex encoded) and your goal is to recover the plaintext and enter it in the input boxes provided below. For an implementation of AES you may use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), Java. 
As a test, send the last two tasks to some of your colleagues to check whether your encryption is correct. You can do this work in pairs.  Submit the implementation and a paper describing your solution.
Challenge: As learning experience, it would be nice if you implement CBC and CTR modes yourself. (Strongly recommended for the ones that are doing a PhD). 


Task 1 
•	CBC key: 140b41b22a29beb4061bda66b6747e14
•	CBC Ciphertext: 
4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee\ 
2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81

Task 2
•	CBC key: 140b41b22a29beb4061bda66b6747e14
•	CBC Ciphertext:
5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48\
e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253

Task 3
•	CTR key: 36f18357be4dbd77f050515c73fcf9f2
•	CTR Ciphertext: 
69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc3\ 
88d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329

Task 4
•	CTR key: 36f18357be4dbd77f050515c73fcf9f2
•	CTR Ciphertext: 
770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa\ 
0e311bde9d4e01726d3184c34451

Task 5
•	CTR key: 36f18357be4dbd77f050515c73fcf9f2
•	CTR Plaintext: 
5468697320697320612073656e74656e636520746f20626520656e63727970746564207573696e67204145532061 6e6420435452206d6f64652e

Task 6
•	CBC key: 140b41b22a29beb4061bda66b6747e14
•	CBC Plaintext:
4e657874205468757273646179206f6e65206f66207468652062657374207465616d7320696e2074686520776f726c642077696c6c2066616365206120626967206368616c6c656e676520696e20746865204c696265727461646f72657320646120416d6572696361204368616d70696f6e736869702e


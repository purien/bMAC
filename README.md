# bMAC
bMAC.ino (https://github.com/purien/bMAC/blob/master/bMAC.ino) is a test program, written for for Arduino Nano, which implements the  bijective MAC Time Stamped (bMAC_TS) algorithm.

See IETF Draft https://tools.ietf.org/html/draft-urien-core-bmac-05 for details
   
   The goal of the bijective MAC (bMAC) is to compute an integrity value, which cannot be guessed by malicious software. 
   
   In classical keyed MACs, MAC is computing according to a fixed order. 
   
   In the bijective MAC, the content of N addresses {A(0)...A(N-1)} is hashed according to a hash function H, and a permutation P(x) (i.e. bijective application with x in the range 0...N-1) so that : 
    
    bMAC(A, P) = H( A(P(0)) || A(P(1)) ... || A(P(N-1) ).
   
    For time stamped bMAC (bMAC_TS), the computing time (CT) is exored with the bMAC :
    bMAC_TS = bMAC exor CT
    
   The bijective MAC key is the permutation P(x). 
   
   The number of permutations for N addresses is N!, as an illustration 35! is greater than 2^128. So the bMAC computation requires the knowledge of the whole space memory. This is trivial for genuine software, but could very difficult for corrupted software, especially for time stamped bMAC.
   
   A corrupted software may use a compression/decompression algorithm in order to compute a correct bMAC value. The basic principle of the time stamped bMAC is that the decompression algorithm modifies the time needed for the bMAC computing. Furthermore we assume that the time required by the bMAC computing is dependent on the permutation.
   
   Roughly speaking the bMAC computing time follows a normal distribution.
   
   bMAC.ino demonstration code targets an Arduino nano, including an ATmega328 processor, 16MHz clock, 32KB FLASH (including 2KB bootloader), 2KB SRAM, 1KB EEPROM. 
   
   The ATmega memory size is therefore (32+2+1)KB = 35840 bytes 
   
   The observed computing time average is 6782679 (with 4us resolution i.e. 27,130176s), and standard deviation is 3122 (with 4us resolution, i.e. 12,488 ms). The computing time entropy, for 3 standard devivations (3.3122= 9366) is about 13 bits.
   
   Permutations (P) are based on generators in the group Z/pZ* with p safe prime, p=35879=2q+1 and q=17939 (Sophie Germain prime) with p=7 mod 8. 
   
   Generator gk are computed as gk = p - (2^k mod p), with k in the range 1...q-1
   
   g1 g2 being generators in Z/pZ*, s1 an integer in the range 1...p-1, y in the range 1...p-1, x in the range 0...p-2
   
   F(y) = g2^((s1.g1^y)mod p) mod p 
   
   P(x) = F(x+1)-1
   
   The number of P permutations is (p-1).(q-1)^2 = 11,545,817,414,038 (more than 2^43)
   
   
   
   
   
   
   
  


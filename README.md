# bMAC
Bijective MAC Time Stamped for AVR Arduino
   The goal of the bijective MAC (bMAC) is to compute an integrity value, which cannot be guessed by malicious software. 
   In classical keyed MACs, MAC is computing according to a fixed order. 
   In the bijective MAC, the content of N addresses {A(0)...A(N-1)} is hashed according to a hash function H and a permutation P (i.e. bijective application in the range 0,N-1 o that : 
    
    bMAC(A, P) = H( A(P(0)) || A(P(1)) ... || A(P(N-1) ).
   
    For time stamped bMAC, the computing time is exored with the bMAC
    
   The bijective MAC key is the permutation P. The number of permutations for N addresses is N!, as an illustration 35! is 
   greater than 2^128. So the bMAC computation requires the knowledge of the whole space memory. This is trivial for genuine software, but could very difficult for corrupted software, especially for time stamped bMAC. 

# HHE-PPML: Privacy-Preserving Machine Learning Through Hybrid Homomorphic Encryption
A Privacy-Preserving Machine Learning (PPML) protocol that is resource friendly to edge devices using Hybrid Homomorphic Encryption.

## Requirements
`cpp==9.4.0`   
`CMAKE>=3.13`  
`SEAL==4.0.0`  

[Here](https://github.com/microsoft/SEAL) are the instructions for installing the Microsoft's SEAL library. Our code are developed based on the [PASTA framework for HHE](https://github.com/IAIK/hybrid-HE-framework).

## Structure
## Repository Structure
```
├── configs              
│   ├── config.cpp  # hold the configurations (HE parameters, number of runs for experiments...)
├── experiments     # ho 
├── asio-1.24.0  # the library for  
├── notebooks 
├── outputs
├── src  
|   ├── client.py  # code for the client
|   ├── server.py  # code for the server
└── weights
 ```

## Running
In the terminal, `cd` into the project's directory, then run
- `cmake -S . -B build`  
- `cmake --build build`  
- Then, run the produced executables in `./build`. For example, the result of running `./build/simple_hhe` can be something like in the figure below
![one_party_hhe](./images/one_party_hhe_run.png)
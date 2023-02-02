# HHE-PPML: Privacy-Preserving Machine Learning Through Hybrid Homomorphic Encryption
A Privacy-Preserving Machine Learning (PPML) protocol that is resource friendly to edge devices using Hybrid Homomorphic Encryption.

## Requirements
`cpp==9.4.0`   
`CMAKE>=3.13`  
`SEAL==4.0.0`  

The [Microsoft SEAL library](https://github.com/microsoft/SEAL) is already installed in `libs/seal`. Also, our code are developed based on the [PASTA framework for HHE](https://github.com/IAIK/hybrid-HE-framework).

## Repository Structure
```
├── configs              
│   ├── config.cpp  # hold the configurations (HE parameters, number of runs for experiments...)
├── experiments     # hold the code for the experiments reported in the paper
├── images          # hold the images in `README.md`
├── protocols       # hold the demo code for the protocols in the paper
├── src             # hold the components needed to build the protocols 
├── tests           # hold the unit tests
└── util            # hold the utility code used in PASTA and for data communication via sockets
 ```

## Running
In the terminal, `cd` into the project's directory, then run
- `cmake -S . -B build -DCMAKE_PREFIX_PATH=libs/seal`  
- `cmake --build build`  
- Then, run the produced executables in `./build`. For example running `./build/simple_hhe` will produce something similar to the figure below
![one_party_hhe](./images/one_party_hhe_run.png)
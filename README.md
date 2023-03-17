# BLAKE2s Hash function: BS and MS Project- IISERB(2022-23)

Under the MS project, the working principles, methods and optimsations over BLAKE was studied and used to implement the BLAKE2s hash function. It can produce hash for a given string or any binary file using CLI. Also, properties of BLAKE2s were analysed and preimage attacks were mounted on the round-reduced(i.e. 1.5 and 2 rounds) versions. This repository contains both the works combined and uses C/C++ programming language for implementation of the functions and attacks.
## Author

- [@ajaycc17](https://www.github.com/ajaycc17)

## Under guidance of

- Dr Shashank Singh([IISER Bhopal](https://sites.google.com/view/shashank))


## Acknowledgements

 - Jean-Philippe Aumasson, Luca Henzen, Willi Meier, Raphael C.-W. Phan: [Sha-3 proposal blake. Submission to NIST (2008)](https://www.aumasson.jp/blake/blake.pdf)
 - Ji, L., Liangyu, X.: Attacks on round-reduced BLAKE. [Cryptology ePrint Archive, Report 2009/238 (2009)](https://eprint.iacr.org/2009/238.pdf)
 - Jean-Philippe Aumasson, Jian Guo, Simon Knellwolf, Krystian Matusiewicz, and Willi Meier: [Differential and invertibility properties of BLAKE (full version). [Cryptology ePrint Archive, Report 2010/043 (2010)](https://eprint.iacr.org/2010/043.pdf)
 - Aumasson, J.P., Samuel N., Z. Wilcox-O'Hearn, and Christian W.: [BLAKE2: simpler, smaller, fast as MD5.Cryptology ePrint Archive, Report 2013/322 (2013)](https://eprint.iacr.org/2013/322.pdf)
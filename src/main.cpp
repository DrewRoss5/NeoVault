#include <iostream>
#include <sodium/randombytes.h>
#include "cryptoutils.h"

using namespace crypto;

int main(int argc, char* argv[]){
    if (argc != 2){
        std::cout << "Please provide exactly one argument (a sample password) for this demo" << std::endl;
    }
    // create the cipherfile 
    CipherFile cipher("../test/example1.txt", argv[1]);
    // display the encrypted and decrypted versions of the file 
    std::cout << "Exported Ciphertext: " << hex_string(cipher.export_ciphertext().get(), cipher.size()) << "\nDecrypted Plaintext: " << (char*) cipher.decrypt(argv[1]).get() << std::endl;
    std::cout << "\nOther information:\n" << "\tNonce: " << hex_string(cipher.nonce(), NONCE_SIZE) << "\n\tSalt: " << hex_string(cipher.salt(), SALT_SIZE) << std::endl;

    


}
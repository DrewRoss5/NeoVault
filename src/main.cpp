#include <iostream>
#include <fstream>
#include <sodium/randombytes.h>
#include "cryptoutils.h"

using namespace crypto;

int main(int argc, char* argv[]){
    if (argc != 3){
        std::cout << "This demo takes exactly two arugments." << std::endl;
        return 1;
    }
    // determine the command the user wants to run 
    std::string command(argv[1]);
    if (command == "encrypt_f"){
        // get the password to encrypt the file with 
        std::string password;
        std::cout << "Password: ";
        std::getline(std::cin, password);
        // attempt to encrypt the provided file
        try{
            CipherFile ciphertext(argv[2], password);
            // export the encrypted files
            std::basic_ofstream<unsigned char> out_file(argv[2], std::ios::binary);
            out_file << ciphertext;
            out_file.close();
            std::cout << "File Encrypted Succesfully" << std::endl;
        }
        catch (std::exception err){
            std::cout << err.what() << std::endl;
            return 1;
        }
    }
    else if (command == "decrypt_f"){
        // get the password to decrypt the file with 
        std::string password;
        std::cout << "Password: ";
        std::getline(std::cin, password);
        // attempt to decrypt the file 
        try{
            // import the ciphertext
            CipherFile ciphertext;
            std::basic_ifstream<unsigned char> in_file(argv[2], std::ios::binary);
            in_file >> ciphertext;
            in_file.close();
            // export the plaintext
            std::unique_ptr<unsigned char[]> plaintext = ciphertext.decrypt(password);
            std::basic_ofstream<unsigned char> out_file(argv[2]);
            out_file.write(plaintext.get(), (ciphertext.size() - AES_OVERHEAD_SIZE));    
            out_file.close();
            std::cout << "File Decrypted Succesfully" << std::endl;
        }
        catch (std::exception err){
            std::cout << err.what() << std::endl;
            return 1;            
        }
    }
    else
        std::cout << "Unrecognized Command: \"" << command << "\"" << std::endl;
}
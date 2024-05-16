#include <iostream>
#include <fstream>
#include <memory>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdexcept>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/randombytes.h>
#include "cryptoutils.h"

// cipherfile functions 
crypto::CipherFile::CipherFile(const std::string& file_path, const std::string& password){
    // create the key, and salt
    unsigned char key[KEY_SIZE];
    salt_ = new unsigned char[SALT_SIZE];
    gen_salt(salt_);
    // hash the password and encrypt
    hash_key(password, salt_, key);
    encrypt_(file_path, key);

}

crypto::CipherFile::CipherFile(const std::string& file_path, const unsigned char key[]){
    salt_ = nullptr;
    encrypt_(file_path, key);
}

crypto::CipherFile::CipherFile(unsigned char* in, size_t ciphertext_size){
    std::cout << "File Content: " << hex_string(in, ciphertext_size) << std::endl;
    in = 0;
    // raise an error if the ciphertext is too small
    if (ciphertext_size < HEADER_SIZE+AES_OVERHEAD_SIZE+1)
        throw std::invalid_argument("Invalid Ciphertext Size");
    size_ = ciphertext_size - HEADER_SIZE;
    // create buffers for salt, nonce, and ciphertext
    salt_ = new unsigned char[SALT_SIZE];
    nonce_ = new unsigned char[NONCE_SIZE];
    ciphertext_ = new unsigned char[size_];
    // parse the salt, nonce, and ciphertext

    std::memcpy(salt_, in, SALT_SIZE);
    std::memcpy(nonce_, in + SALT_SIZE, NONCE_SIZE);
    std::memcpy(ciphertext_, in + HEADER_SIZE, size_);
}

crypto::CipherFile::CipherFile(std::string file_path){
    // open the file and ensure it exits
    std::basic_fstream<unsigned char> in(file_path);
    if (!in.good())
        throw std::exception("Invalid Input File!");
    // determine the filesize
    in.seekg(0, in.end);
    size_t file_size = in.tellg();
    in.seekg(0, in.beg);
    // read the file into a single buffer
    unsigned char* file_buf = new unsigned char[file_size];
    in.read(file_buf, file_size);
    in.close();
    // define the size and create buffers
    size_ = file_size - HEADER_SIZE;
    salt_ = new unsigned char[SALT_SIZE];
    nonce_ = new unsigned char[NONCE_SIZE];
    ciphertext_ = new unsigned char[size_];
    // parse the ciphertext file into its components
    std::memcpy(salt_, file_buf, SALT_SIZE);
    std::memcpy(nonce_, file_buf + SALT_SIZE, NONCE_SIZE);
    std::memcpy(ciphertext_, file_buf + HEADER_SIZE, size_);
    delete file_buf;
    
}

// sets the ciphertext, nonce, and size, whilst encrypting the file at the provided path
void crypto::CipherFile::encrypt_(const std::string& file_path, const unsigned char key[]){
    // ensure the file exists and open it 
    std::basic_fstream<unsigned char> in_stream(file_path);
    if (!in_stream.good())
        throw std::invalid_argument("The file could not be read");
    // get the size of the of the file
    in_stream.seekg(0, in_stream.end);
    size_t file_size = in_stream.tellg();
    in_stream.seekg(0, in_stream.beg);
    // read the plaintext of the file
    unsigned char* plaintext = new unsigned char[file_size];
    in_stream.read(plaintext, file_size);
    in_stream.close();
    // generate a nonce
    nonce_ = new unsigned char[NONCE_SIZE];
    gen_nonce(nonce_);
    // encrypt the ciphertext
    size_ = AES_OVERHEAD_SIZE + file_size;
    ciphertext_ = new unsigned char[size_];
    crypto_secretbox_easy(ciphertext_, plaintext, file_size, nonce_, key);
    // free the memory allocated to the plaintext
    delete plaintext;
}

// decrypts the file with a salt and returns a unique pointer to the plaintext
std::unique_ptr<unsigned char[]> crypto::CipherFile::decrypt(const std::string& password){
    // raise an error if there is no salt (implying the file was not encrypted with a password)
    if (salt_ == nullptr)
        throw std::exception("This cipertext cannot be decrypted with a password");
    // hash the key and decrypt the file 
    unsigned char key[KEY_SIZE];
    hash_key(password, salt_, key);
    return std::move(decrypt(key));
}

// decrypts the file and returns a unique pointer to the plaintext
std::unique_ptr<unsigned char[]> crypto::CipherFile::decrypt(unsigned char* key){
    // create a buffer for the plaintext
    unsigned char *plaintext = new unsigned char[size_ - AES_OVERHEAD_SIZE];
    if (crypto_secretbox_open_easy(plaintext, ciphertext_, size_, nonce_, key) != 0){
        throw std::invalid_argument("Failed to decrypt ciphertext");
    }
    return std::unique_ptr<unsigned char[]>(plaintext);
}

// exports the encrypted ciphertext, complete with salt and nonce
std::unique_ptr<unsigned char[]> crypto::CipherFile::export_ciphertext(){
    // write the salt to a buffer to export, if present, otherwise, write all zeroes
    unsigned char salt_buf[SALT_SIZE];
    if (salt_){
        unsigned char* tmp = salt_;
        for (int i = 0; i < SALT_SIZE; i++)
            salt_buf[i] = tmp[i];
    }
    else{
        for(int i = 0; i < SALT_SIZE; i++)
            salt_buf[i] = 0;
    }
    // generate the buffer to write to 
    std::unique_ptr<unsigned char[]> export_buf(new unsigned char[size_ + HEADER_SIZE]);
    // wriste the  salt, nonce, and ciphertext to buffer
    unsigned char* tmp = export_buf.get();
    memcpy(tmp, salt_buf, SALT_SIZE);
    memcpy(tmp + SALT_SIZE, nonce_, NONCE_SIZE);
    memcpy(tmp + HEADER_SIZE, ciphertext_, size_);
    return std::move(export_buf);
}

// writes the exported ciphertext to a file 
std::basic_ofstream<unsigned char>& crypto::CipherFile::write_to_file(std::basic_ofstream<unsigned char>& out){
    out.write(export_ciphertext().get(), size_ + HEADER_SIZE);
    return out;
}

// deallocates memory for the cipherfile class
crypto::CipherFile::~CipherFile(){
    delete salt_;
    delete nonce_;
    delete ciphertext_;
}

// extraction operator for the cipherfile class
std::basic_ofstream<unsigned char>& operator<<(std::basic_ofstream<unsigned char>&stream, crypto::CipherFile& ciphertext){
    return ciphertext.write_to_file(stream);
}

// fills a salt-sized buffer with random bytes
void crypto::gen_salt(unsigned char salt[]){
    randombytes_buf(salt, SALT_SIZE);
}

// fills a nonce-sized buffer with random bytes
void crypto::gen_nonce(unsigned char nonce[]){
    randombytes_buf(nonce, NONCE_SIZE);
}

// hashes a password with a provided salt, and writes the resulting 32-bit key to a provided buffer
void crypto::hash_key(std::string password, const unsigned char salt[], unsigned char key[]){
    const char* pw_c_str = password.c_str();
    // create the hash
    crypto_hash_sha256_state key_state;
    crypto_hash_sha256_init(&key_state);
    // push the password and key to the hash
    crypto_hash_sha256_update(&key_state, (const unsigned char*) pw_c_str, strlen(pw_c_str));
    crypto_hash_sha256_update(&key_state, salt, SALT_SIZE);
    // update the provided key buffer
    crypto_hash_sha256_final(&key_state, key);
}

// takes an unsigned byte array and converts it to a hex string 
std::string crypto::hex_string(const unsigned char bytes[], size_t size){
    std::stringstream ss;
    for (int i = 0; i < size; i++)
        ss << std::setw(2) << std::hex << std::setfill('0') << (int) bytes[i];
    return ss.str();
}

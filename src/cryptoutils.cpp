#include <fstream>
#include <filesystem>
#include <memory>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdexcept>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/randombytes.h>
#include "cryptoutils.h"

namespace fs = std::filesystem;

// cipherfile functions 
crypto::CipherFile::CipherFile(const std::string& file_path, const std::string& password){
    // create the key, and salt
    unsigned char key[KEY_SIZE];
    salt_ = new unsigned char[SALT_SIZE];
    gen_salt(salt_);
    // hash the password and encryptf
    hash_key(password, salt_, key);
    encrypt_(file_path, key);
}

crypto::CipherFile::CipherFile(const std::string& file_path, const unsigned char key[]){
    salt_ = nullptr;
    encrypt_(file_path, key);
}

crypto::CipherFile::CipherFile(unsigned char* in, size_t ciphertext_size){
    import_(in, ciphertext_size);
}

crypto::CipherFile::CipherFile(std::string file_path){
    // open the file and ensure it exits
    std::basic_ifstream<unsigned char> in(file_path, std::ios_base::binary);
    if (!in.good())
        throw std::exception("Invalid Input File!");
    import_from_file_(in);
    in.close();
}

// sets the ciphertext, nonce, and size, whilst encrypting the file at the provided path
void crypto::CipherFile::encrypt_(const std::string& file_path, const unsigned char key[]){
    // ensure the file exists and open it 
    std::basic_fstream<unsigned char> in_stream(file_path);
    if (!in_stream.good())
        throw std::invalid_argument("The file could not be read");
    // get the size of the file
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
    delete[] plaintext;
}

// imports ciphertext from an unsigned char array of exported ciphertext
void crypto::CipherFile::import_(unsigned char* in, size_t ciphertext_size){
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

// imports ciphertext from a file stream of an exported ciphertext file
void crypto::CipherFile::import_from_file_(std::basic_istream<unsigned char>& in_stream){
    // get the size of the file
    in_stream.seekg(0, in_stream.end);
    size_t file_size = in_stream.tellg();
    in_stream.seekg(0, in_stream.beg);
    // read the file to a buffer 
    unsigned char* file_buf = new unsigned char[file_size];
    in_stream.read(file_buf, file_size);
    // import the file's contents
    import_(file_buf, file_size);
    delete[] file_buf;
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
    if (salt_)
        delete[] salt_;
    delete[] nonce_;
    delete[] ciphertext_;
}

// extraction operator for the cipherfile class
std::basic_ofstream<unsigned char>& crypto::operator<<(std::basic_ofstream<unsigned char>&stream, crypto::CipherFile& ciphertext){
    return ciphertext.write_to_file(stream);
}

// reads exported ciphertext from a file stream
std::basic_ifstream<unsigned char>& crypto::operator>>(std::basic_ifstream<unsigned char>&stream, crypto::CipherFile& file){
    file.import_from_file_(stream);
    return stream;
}

// vault constuctors 
crypto::Vault::Vault(std::string path, unsigned char* master_key){
    path_ = path;
    // generate a random salt and nonce
    salt_ = new unsigned char[SALT_SIZE];
    nonce_ = new unsigned char[NONCE_SIZE];
    gen_salt(salt_);
    gen_nonce(nonce_);
    // hash the master key and encrypt the vault
    unsigned char* key = new unsigned char[KEY_SIZE];
    hash_key_(master_key, salt_, key, KEY_SIZE);
    encrypt_(key);
    delete[] key;
}

crypto::Vault::Vault(std::string path, std::string password){
    path_ = path;
    // generate a random salt and nonce
    salt_ = new unsigned char[SALT_SIZE];
    nonce_ = new unsigned char[NONCE_SIZE];
    gen_salt(salt_);
    gen_nonce(nonce_);
    // hash the password into a 256-bit key
    unsigned char* key = new unsigned char[KEY_SIZE];
    unsigned char* pw_bytes = (unsigned char*) password.c_str();
    hash_key_(pw_bytes, salt_, key, password.size());
    encrypt_(key);
    delete[] key;
}

void crypto::Vault::encrypt_(unsigned char* key){
    std::string tmp_path;
    for (const auto& child : fs::directory_iterator(path_)){
        tmp_path = child.path().string();
        // validate the path name
        if (tmp_path.find(';') != std::string::npos || tmp_path.find('?') != std::string::npos)
            throw std::exception("Plaintext files must not have any of the following in their names: ;?");
        if (fs::is_directory(child)){
            // create a new encrypted vault
            subdirectories_.push_back(new Vault(tmp_path, key));
        }
        else{
            file_names_.push_back(get_base_path(tmp_path));
            // read a new cipherfile from the path
            files_.push_back(new CipherFile(tmp_path, key));
        }
    }
}

// hashes a key, be it bytes from a password or a master key, with a salt
void crypto::Vault::hash_key_(unsigned char* plaintext, const unsigned char* salt, unsigned char* key, size_t plaintext_size){
    crypto_hash_sha256_state key_state;
    crypto_hash_sha256_init(&key_state);
    // update the key state with the master key and salt
    crypto_hash_sha256_update(&key_state, salt, SALT_SIZE);
    crypto_hash_sha256_update(&key_state, plaintext, plaintext_size);
    // update the key
    crypto_hash_sha256_final(&key_state, key);
}

// decrypts the vault and outputs it's contents to a provided path
void crypto::Vault::decrypt(std::string out_path, unsigned char* key){
    fs::create_directory(out_path);
    size_t file_count = files_.size();
    size_t subdir_count = subdirectories_.size();
    // decrypt all individual files 
    for(int i = 0; i < file_count; i++){
        std::basic_ofstream<unsigned char> out(out_path + '\\' + file_names_[i], std::ios::binary);
        out.write(files_[i]->decrypt(key).get(), files_[i]->size());
        out.close();
        //delete[] files_[i];
    }
    // decrypt all subdirectories
    unsigned char tmp_key[KEY_SIZE];
    for (int i = 0; i < subdir_count; i++){
        hash_key_(key, subdirectories_[i]->salt(), tmp_key, KEY_SIZE);
        subdirectories_[i]->decrypt(out_path, tmp_key);
    }
}

// decrypts the vault with a password
void crypto::Vault::decrypt(std::string out_path, std::string password){
    // hash the password
    unsigned char key[KEY_SIZE];
    unsigned char* pw_bytes = (unsigned char*) password.c_str();
    hash_key_(pw_bytes, salt_, key, password.size());
    // decrypt the vault
    decrypt(out_path, key);
}

crypto::Vault::~Vault(){
    delete[] nonce_;
    delete[] salt_;
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

// returns a string of a file path with leading paths stripped
std::string crypto::get_base_path(std::string file_path){
    if (file_path.find('\\') != std::string::npos)
        return file_path.substr(file_path.find_last_of('\\') + 1);
    else
        return file_path;
}
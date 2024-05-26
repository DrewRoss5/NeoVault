#include <fstream>
#include <stack>
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
    std::basic_fstream<unsigned char> in(file_path, std::ios_base::binary);
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
    size_t file_size = get_file_size(in_stream);
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
void crypto::CipherFile::import_from_file_(std::basic_fstream<unsigned char>& in_stream){
    size_t file_size = get_file_size(in_stream);
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
std::basic_ofstream<unsigned char>& crypto::operator<<(std::basic_ofstream<unsigned char>& stream, crypto::CipherFile& ciphertext){
    return ciphertext.write_to_file(stream);
}

// reads exported ciphertext from a file stream
std::basic_fstream<unsigned char>& crypto::operator>>(std::basic_fstream<unsigned char>&stream, crypto::CipherFile& file){
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

crypto::Vault::Vault(std::string vault_path, unsigned char* vault_nonce, unsigned char* vault_salt){
    path_ = vault_path;
    nonce_ = vault_nonce;
    salt_ = vault_salt;
}

crypto::Vault crypto::Vault::import_vault(std::string path){
    std::basic_fstream<unsigned char> in(path, std::ios::binary);
    if (!in.good())
        throw std::exception("Failed to read vault file");
    // read the file's contents to a buffer
    size_t file_size = get_file_size(in);
    unsigned char* file_buf = new unsigned char[file_size];
    in.read(file_buf, file_size);
    // get the size of the encrypted file table 
    char tmp;
    std::string size_str;
    int pos = 0;
    while (tmp != ';'){
        if (tmp != ';')
            size_str.push_back(file_buf[pos]);
        tmp = file_buf[pos];
        pos++;
    }
    size_t table_size = std::stoi(size_str);
    // decrypt and parse the table
    unsigned char* table_buf = new unsigned char[table_size];
    std::memcpy(table_buf, file_buf + pos - 1, table_size);
    pos += table_size;

    
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
    }
    // decrypt all subdirectories
    unsigned char tmp_key[KEY_SIZE];
    for (int i = 0; i < subdir_count; i++){
        hash_key_(key, subdirectories_[i]->salt(), tmp_key, KEY_SIZE);
        subdirectories_[i]->decrypt(out_path + '\\' + get_base_path(subdirectories_[i]->path()), tmp_key);
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

// creates a string listing all files (with their respective sizes) and subdirectories in vault
std::string crypto::Vault::create_file_table(){
    size_t file_count = files_.size();
    size_t subdir_count = subdirectories_.size();
    std::stringstream table;
    table << "BD" << path_ << '?' << hex_string(salt_, SALT_SIZE) << hex_string(nonce_, NONCE_SIZE) << ';';
    for (int i = 0; i < file_count; i++)
        table << "BF" << file_names_[i] << '?' << files_[i]->size() + HEADER_SIZE << ';';
    for (int i = 0; i < subdir_count; i++)
        table << subdirectories_[i]->create_file_table() << ";";
    table << "ED";
    return table.str();
}

/*
    encrypts all files and writes the ciphertexts of them to a provided stream. 
    This simply writes the files of this vault and all subvaults, under the assumption a file table has been provided
*/
void crypto::Vault::export_vault_(std::basic_ofstream<unsigned char>& out){
    size_t file_count = files_.size();
    size_t subdir_count = subdirectories_.size();
    for (int i = 0; i < file_count; i++)
        files_[i]->write_to_file(out);
    for (int i = 0; i < subdir_count; i++)
        subdirectories_[i]->export_vault_(out);
}

std::basic_ofstream<unsigned char>& crypto::Vault::write_to_file(std::basic_ofstream<unsigned char>& out, std::string password){
    // generate a nonce and salt for the file table
    unsigned char table_salt[SALT_SIZE];
    unsigned char table_nonce[NONCE_SIZE];
    gen_nonce(table_nonce);
    gen_salt(table_salt);
    // generate the file table
    std::string tmp_table = create_file_table();
    unsigned char* table = (unsigned char*) tmp_table.c_str();
    size_t table_size = tmp_table.size();
    // hash the key
    unsigned char key[KEY_SIZE];
    unsigned char* pw_bytes = (unsigned char*) password.c_str();
    hash_key_(pw_bytes, table_salt, key, strlen((char*) pw_bytes));
    // encrypt the table 
    size_t ciphertext_size = table_size + AES_OVERHEAD_SIZE;
    unsigned char* table_ciphertext = new unsigned char[ciphertext_size];
    crypto_secretbox_easy(table_ciphertext, table, table_size, table_nonce, key);
    // write the length to the file
    std::string len_str =  std::to_string(ciphertext_size);
    out << len_str.c_str()  << ';';
    out << table_ciphertext;
    out << table_salt;
    out << table_nonce;
    export_vault_(out);
    return out;
}


crypto::Vault::~Vault(){
    delete[] nonce_;
    delete[] salt_;
    size_t file_count = files_.size();
    size_t subdir_count = subdirectories_.size();
    for (int i = 0; i < file_count; i++)
        delete[] files_[i];
    for (int i = 0; i < subdir_count; i++)
        delete subdirectories_[i];
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

// returns the size of a file stream
size_t crypto::get_file_size(std::basic_fstream<unsigned char>& in){
    in.seekg(0, in.end);
    size_t file_size = in.tellg();
    in.seekg(0, in.beg);
    return file_size;
}
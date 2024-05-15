#include <memory>
#include <vector>
#include <string>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_hash_sha256.h>

#ifndef CRYPTO_UTILS
#define CRYPTO_UTILSss

#define KEY_SIZE 32
#define SALT_SIZE 16
#define AES_OVERHEAD_SIZE crypto_secretbox_MACBYTES
#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define HEADER_SIZE SALT_SIZE + NONCE_SIZE

namespace crypto{
    // a class representing a single encrypted file
    class CipherFile{
        private:
            size_t size_;
            std::unique_ptr<unsigned char[]> nonce_;
            std::unique_ptr<unsigned char[]> salt_;
            std::unique_ptr<unsigned char[]> ciphertext_;
            void encrypt_(const std::string& file_path, const unsigned char key[]);
        public:
            CipherFile(const std::string& file_path, const std::string& password);
            CipherFile(const std::string& file_path, const unsigned char key[]);
            CipherFile(unsigned char in[], size_t ciphertext_size);  
            static CipherFile import_file(std::string file_path);
            std::unique_ptr<unsigned char[]> decrypt(unsigned char key[]);
            std::unique_ptr<unsigned char[]> decrypt(const std::string& password);
            std::unique_ptr<unsigned char[]> export_ciphertext();
            std::basic_ofstream<unsigned char>& write_to_file(std::basic_ofstream<unsigned char>&);
            // operators 
            friend std::basic_ofstream<unsigned char>& operator<<(std::basic_ofstream<unsigned char>&stream, CipherFile& file);
            // simple getters 
            const size_t size() {return size_;}
            const unsigned char* nonce() {return nonce_.get();}
            const unsigned char* content() {return ciphertext_.get();}
            const unsigned char* salt() {return salt_.get();}
    };

    // a class representing an encrypted directory 
    class Vault{
        private:
            std::string parent_path;
            std::vector<Vault> subdirectories_;
            std::vector<CipherFile> files_;
            std::unique_ptr<unsigned char[]> nonce_;
            std::unique_ptr<unsigned char[]> salt_;
        public:
            std::unique_ptr<unsigned char[]> export_vault();
            std::unique_ptr<unsigned char[]> decrypt(unsigned char* key);
            std::basic_ofstream<unsigned char>& write(std::basic_ofstream<unsigned char>&);
    };

    // other "utility" functions
    void gen_salt(unsigned char salt[]);
    void gen_nonce(unsigned char nonce[]);
    void hash_key(std::string password, const unsigned char salt[], unsigned char key[]);
    std::string hex_string(const unsigned char bytes[], size_t size);
}

#endif 

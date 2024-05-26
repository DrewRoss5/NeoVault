#include <memory>
#include <vector>
#include <string>
#include <sodium/core.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_hash_sha256.h>

#ifndef CRYPTO_UTILS
#define CRYPTO_UTILSss

#define KEY_SIZE 32
#define SALT_SIZE 16
#define AES_OVERHEAD_SIZE crypto_secretbox_MACBYTES
#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define HEADER_SIZE (NONCE_SIZE + SALT_SIZE)

namespace crypto{
    // a class representing a single encrypted file
    class CipherFile{
        private:
            size_t size_;
            unsigned char* nonce_;
            unsigned char* salt_;
            unsigned char* ciphertext_;
            void encrypt_(const std::string& file_path, const unsigned char key[]);
            void import_(unsigned char* in, size_t ciphertext_size);
            void import_from_file_(std::basic_fstream<unsigned char>& in);
        public:
            CipherFile() : nonce_(nullptr), salt_(nullptr), ciphertext_(nullptr), size_(0) {}
            CipherFile(const std::string& file_path, const std::string& password);
            CipherFile(const std::string& file_path, const unsigned char key[]);
            CipherFile(unsigned char* in, size_t ciphertext_size);  
            CipherFile(std::string file_path);
            std::unique_ptr<unsigned char[]> decrypt(unsigned char key[]);
            std::unique_ptr<unsigned char[]> decrypt(const std::string& password);
            std::unique_ptr<unsigned char[]> export_ciphertext();
            std::basic_ofstream<unsigned char>& write_to_file(std::basic_ofstream<unsigned char>&);
            // operators 
            friend std::basic_ofstream<unsigned char>& operator<<(std::basic_ofstream<unsigned char>&stream, CipherFile& file);
            friend std::basic_fstream<unsigned char>& operator>>(std::basic_fstream<unsigned char>&stream, CipherFile& file);
            // simple getters 
            const size_t size() {return size_;}
            const unsigned char* nonce() {return nonce_;}
            const unsigned char* content() {return ciphertext_;}
            const unsigned char* salt() {return salt_;}
            ~CipherFile();
    };

    // a class representing an encrypted directory 
    class Vault{
        private:
            std::string path_;
            std::vector<Vault*> subdirectories_;
            std::vector<CipherFile*> files_;
            std::vector<std::string> file_names_;
            unsigned char* nonce_;
            unsigned char* salt_;
            void encrypt_(unsigned char* key);
            void hash_key_(unsigned char* plaintext, const unsigned char* salt, unsigned char* key, size_t plaintext_size);
            void export_vault_(std::basic_ofstream<unsigned char>&);
            void add_child(CipherFile& cipher, std::string file_name);
        public:
            Vault(std::string path, std::string password);
            Vault(std::string path, unsigned char* master_key);
            Vault(std::string path, unsigned char* nonce, unsigned char* salt);
            static Vault import_vault(std::string path);
            void decrypt(std::string out_path, unsigned char* key);
            void decrypt(std::string out_path, std::string password);
            std::basic_ofstream<unsigned char>& write_to_file(std::basic_ofstream<unsigned char>& in, std::string password);
            std::string create_file_table();
            // simple getters
            const std::string path() {return path_;}
            const unsigned char* nonce() {return nonce_;}
            const unsigned char* salt() {return salt_;}
            ~Vault();
    };
    // other "utility" functions
    void gen_salt(unsigned char salt[]);
    void gen_nonce(unsigned char nonce[]);
    void hash_key(std::string password, const unsigned char salt[], unsigned char key[]);
    std::string hex_string(const unsigned char bytes[], size_t size);
    std::string get_base_path(std::string file_path);
    size_t get_file_size(std::basic_fstream<unsigned char>& in);
}

#endif 

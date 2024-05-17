cmake_minimum_required(VERSION 3.28)

# create the project and set the C++ version
project(DirectoryEncryptor)

# enforce the use of C++17
set(CMAKE_CXX_STANDARD 17)

# include vcpkg
include(${VCPKG_CMAKE})

# include libsodium
find_package(unofficial-sodium CONFIG REQUIRED)

# set directory varaiables 
set(SOURCE_DIR "src/")

# create the executable 
add_executable(NeoVault ${SOURCE_DIR}main.cpp ${SOURCE_DIR}cryptoutils.h ${SOURCE_DIR}cryptoutils.cpp)
target_link_libraries(NeoVault unofficial-sodium::sodium)

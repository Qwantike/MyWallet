# Version minimale requise de CMake
cmake_minimum_required(VERSION 3.10)

# Nom du projet
project(ColdWallet)

# Spécification du standard C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Trouver la bibliothèque OpenSSL
find_package(OpenSSL REQUIRED)

# Ajouter les répertoires d'includes
include_directories(
    ${CMAKE_SOURCE_DIR}/libs/json-develop/single_include  # Bibliothèque JSON
    ${CMAKE_SOURCE_DIR}/include                           # Répertoire des fichiers d'en-tête de ton projet
    ${OPENSSL_INCLUDE_DIR}                                # Répertoire des en-têtes OpenSSL
)


# Ajouter les fichiers source à compiler
set(SOURCES
    src/main.cpp
    src/Wallet.cpp
    src/KeyGeneration.cpp
    src/Transaction.cpp
    src/Utils.cpp
    src/WalletSecurity.cpp
)

# Créer l'exécutable à partir des fichiers sources
add_executable(cold_wallet ${SOURCES})

# Lier la bibliothèque OpenSSL à ton projet
target_link_libraries(cold_wallet OpenSSL::Crypto OpenSSL::SSL)

# (Optionnel) Si tu utilises des bibliothèques supplémentaires à l'avenir, tu peux les lier ici
# target_link_libraries(cold_wallet <nom_de_bibliothèque>)

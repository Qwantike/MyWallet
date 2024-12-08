#include "WalletSecurity.h"
#include <openssl/evp.h>  // Pour AES
#include <openssl/rand.h> // Pour générer des IV aléatoires
#include <openssl/err.h>  // Pour l'affichage des erreurs OpenSSL
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>

using namespace std;

string WalletSecurity::askForPassphrase()
{
    vector<string> passphraseWords; // Vecteur pour stocker les mots de la passphrase
    string word;

    cout << "Veuillez entrer votre passphrase (12 mots) un par un :\n";

    // Demander 12 mots à l'utilisateur
    for (int i = 1; i <= 12; ++i)
    {
        cout << "Mot " << i << ": ";
        cin >> word;                     // Lire un mot à la fois
        passphraseWords.push_back(word); // Ajouter le mot au vecteur
    }

    // Concaténer les mots pour former une chaîne unique séparée par des espaces
    ostringstream passphraseStream;
    for (const auto &w : passphraseWords)
    {
        passphraseStream << w << " ";
    }

    string passphrase = passphraseStream.str();

    // Supprimer l'espace final
    if (!passphrase.empty() && passphrase.back() == ' ')
    {
        passphrase.pop_back();
    }

    return passphrase;
}

string WalletSecurity::securePrivateKey(const string &privateKey, const string &passphrase)
{
    cout << "AFFICHAGE PRIVATEKEY : " << privateKey << endl;
    // Paramètres pour PBKDF2
    const int iterations = 10000; // Nombre d'itérations pour PBKDF2
    unsigned char key[32];        // Clé AES 256 bits
    unsigned char iv[16];         // IV de 128 bits

    // Génération de la clé et de l'IV à partir de la passphrase
    if (!PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.size(), nullptr, 0, iterations, EVP_sha256(), sizeof(key), key))
    {
        throw runtime_error("Erreur lors de la dérivation de la clé.");
    }

    // Génération aléatoire de l'IV
    if (!RAND_bytes(iv, sizeof(iv)))
    {
        throw runtime_error("Erreur lors de la génération de l'IV.");
    }

    // Préparation pour le chiffrement
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw runtime_error("Erreur lors de la création du contexte de chiffrement.");

    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Erreur lors de l'initialisation du chiffrement.");
    }

    // Allocation pour le ciphertext
    unsigned char ciphertext[privateKey.size() + EVP_CIPHER_block_size(cipher)];
    int len = 0, ciphertext_len = 0;

    // Chiffrement des données
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len,
                           reinterpret_cast<const unsigned char *>(privateKey.c_str()), privateKey.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Erreur lors du chiffrement.");
    }
    ciphertext_len += len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Erreur lors de la finalisation du chiffrement.");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Combinaison de l'IV et du ciphertext
    stringstream combinedStream;
    combinedStream.write(reinterpret_cast<const char *>(iv), sizeof(iv));
    combinedStream.write(reinterpret_cast<const char *>(ciphertext), ciphertext_len);

    // Conversion en hexadécimal
    stringstream hexStream;
    for (const auto &byte : combinedStream.str())
    {
        hexStream << hex << setw(2) << setfill('0') << (static_cast<unsigned char>(byte) & 0xff);
    }

    return hexStream.str();
}

string WalletSecurity::decryptPrivateKey(const string &encryptedPrivateKey, const string &passphrase)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32]; // Clé AES 256 bits
    unsigned char iv[16];  // IV de 128 bits

    // Convertir la chaîne hexadécimale en données binaires
    vector<unsigned char> ciphertext;
    for (size_t i = 0; i < encryptedPrivateKey.length(); i += 2)
    {
        string byteString = encryptedPrivateKey.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        ciphertext.push_back(byte);
    }

    // Extraire l'IV des premiers 16 octets du ciphertext
    memcpy(iv, ciphertext.data(), 16);

    // Le reste des données après l'IV constitue le ciphertext chiffré
    vector<unsigned char> encryptedData(ciphertext.begin() + 16, ciphertext.end());

    // Générer la clé à partir de la passphrase
    if (!PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.size(), nullptr, 0, 10000, EVP_sha256(), sizeof(key), key))
    {
        throw runtime_error("Erreur lors de la dérivation de la clé.");
    }

    // Créer un contexte de déchiffrement
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Erreur lors de la création du contexte de déchiffrement.");
    }

    // Initialisation du déchiffrement avec la clé et l'IV extraits
    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Erreur lors de l'initialisation du déchiffrement.");
    }

    // Allocation pour le texte en clair
    vector<unsigned char> plaintext(encryptedData.size());
    int len = 0, plaintext_len = 0;

    // Déchiffrement des données
    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, encryptedData.data(), encryptedData.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Erreur lors du déchiffrement.");
    }
    plaintext_len += len;

    // Finalisation du déchiffrement
    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Erreur lors de la finalisation du déchiffrement.");
    }
    plaintext_len += len;

    // Libération du contexte
    EVP_CIPHER_CTX_free(ctx);

    // Convertir le tableau d'octets en chaîne de caractères et retourner le résultat
    return string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

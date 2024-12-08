#include "KeyGeneration.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>

using namespace std;

void KeyGeneration::generateKeyPair(string &privateKey, string &publicKey)
{
    // Initialiser la courbe elliptique secp256k1
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (key == nullptr)
    {
        cerr << "Erreur lors de la création de la clé." << endl;
        return;
    }

    // Générer la clé privée aléatoire
    if (EC_KEY_generate_key(key) != 1)
    {
        cerr << "Erreur lors de la génération de la clé." << endl;
        EC_KEY_free(key);
        return;
    }

    // Obtenir la clé privée au format hexadécimal
    const BIGNUM *privKey = EC_KEY_get0_private_key(key);
    if (privKey == nullptr)
    {
        cerr << "Erreur lors de la récupération de la clé privée." << endl;
        EC_KEY_free(key);
        return;
    }
    char *privateHex = BN_bn2hex(privKey);
    if (privateHex == nullptr)
    {
        cerr << "Erreur lors de la conversion de la clé privée en hexadécimal." << endl;
        EC_KEY_free(key);
        return;
    }
    privateKey = privateHex;
    OPENSSL_free(privateHex); // Libérer la mémoire allouée par BN_bn2hex

    // Obtenir la clé publique au format compressé
    unsigned char pubKey[65]; // La clé publique compressée fait 33 octets pour secp256k1
    size_t pubKeyLen = EC_POINT_point2oct(
        EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_COMPRESSED, pubKey, sizeof(pubKey), nullptr);
    if (pubKeyLen == 0)
    {
        cerr << "Erreur lors de la récupération de la clé publique." << endl;
        EC_KEY_free(key);
        return;
    }

    stringstream ss;
    for (size_t i = 0; i < pubKeyLen; ++i)
    {
        ss << hex << setw(2) << setfill('0') << (int)pubKey[i];
    }
    publicKey = ss.str();

    // Libérer la mémoire
    EC_KEY_free(key);
}

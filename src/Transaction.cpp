#include "Transaction.h"
#include <openssl/ec.h>      // Pour la gestion des courbes elliptiques
#include <openssl/ecdsa.h>   // Pour les fonctions ECDSA
#include <openssl/obj_mac.h> // Pour les identifiants de courbes (ex: NID_secp256k1)
#include <openssl/bn.h>      // Pour la gestion des grands nombres (BIGNUM)
#include <openssl/sha.h>     // Pour les fonctions de hachage SHA (utilisées avec ECDSA)
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;

Transaction::Transaction(const string &from, const string &to, double amt)
    : fromAddress(from), toAddress(to), amount(amt) {}

void Transaction::displayTransaction() const
{
    cout << "Transaction : " << endl;
    cout << "From : " << fromAddress << endl;
    cout << "To : " << toAddress << endl;
    cout << "Amount : " << amount << " BTC" << endl;
}

json Transaction::toJson() const
{
    json j;
    j["from"] = fromAddress;
    j["to"] = toAddress;
    j["amount"] = amount;
    return j;
}

bool Transaction::saveToFile(const string &filename) const
{
    ifstream inFile(filename);
    json j;

    // Si le fichier existe et contient des données JSON, on charge son contenu dans 'j'
    if (inFile.is_open())
    {
        inFile >> j;
        inFile.close();
    }
    else
    {
        j = json::array();
    }

    j.push_back(this->toJson());

    ofstream outFile(filename);
    if (!outFile.is_open())
    {
        cerr << "Erreur lors de l'ouverture du fichier pour sauvegarder la transaction." << endl;
        return false; // Retourne un indicateur d'erreur
    }

    outFile << j.dump(4) << endl;
    outFile.close();
    cout << "Transaction sauvegardée dans " << filename << endl;
    return true; // Indiquer que l'opération a réussi
}

void Transaction::signTransaction(const string &privateKey)
{
    // Convertir la clé privée en format BIGNUM ou EC_KEY
    BIGNUM *privKeyBN = BN_new();
    BN_hex2bn(&privKeyBN, privateKey.c_str());

    // Créer un EC_KEY avec la clé privée
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_private_key(key, privKeyBN);

    // Signature de la transaction (par exemple avec ECDSA)
    unsigned char signature[72];
    unsigned int sig_len;

    if (ECDSA_sign(0, (unsigned char *)this->toJson().dump().c_str(), this->toJson().dump().length(), signature, &sig_len, key) != 1)
    {
        cerr << "Erreur de signature." << endl;
        EC_KEY_free(key);
        BN_free(privKeyBN);
        return;
    }

    // Ajouter la signature à la transaction
    this->signature.assign(signature, signature + sig_len);

    EC_KEY_free(key);
    BN_free(privKeyBN);
}

#ifndef WALLET_SECURITY_H
#define WALLET_SECURITY_H

#include <string>

using namespace std;

class WalletSecurity
{
public:
    // Fonction pour sécuriser une clé privée en utilisant une passphrase
    static string securePrivateKey(const string &privateKey, const string &passphrase);

    // Fonction pour demander une passphrase composée de 12 mots
    static string askForPassphrase();

    // Fonction pour décrypter la clé privée
    static string decryptPrivateKey(const string &encryptedPrivateKey, const string &passphrase);
};

#endif // WALLET_SECURITY_H
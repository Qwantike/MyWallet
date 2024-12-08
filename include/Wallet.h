#ifndef WALLET_H
#define WALLET_H

#include <string>
#include <vector>
#include "KeyGeneration.h"

using namespace std;

class Wallet
{
public:
    Wallet();
    ~Wallet();

    void generateKeys();
    void decryptPrivateKey();
    void savePrivateKey();
    void savePublicKey();
    void createTransaction(const string &toAddress, double amount);

private:
    string privateKey;
    string publicKey;
};

#endif

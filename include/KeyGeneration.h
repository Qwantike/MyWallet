#ifndef KEYGENERATION_H
#define KEYGENERATION_H

#include <string>

using namespace std;

class KeyGeneration
{
public:
    static void generateKeyPair(string &privateKey, string &publicKey);

private:
    static string generateRandomHex(size_t length);
};

#endif

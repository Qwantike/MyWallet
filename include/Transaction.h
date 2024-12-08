#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <string>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

class Transaction
{
private:
    string fromAddress;
    string toAddress;
    double amount;
    vector<unsigned char> signature;

public:
    // Constructeur
    Transaction(const string &from, const string &to, double amt);

    // Affichage de la transaction
    void displayTransaction() const;

    // Sauvegarder la transaction dans un fichier JSON
    bool saveToFile(const string &filename) const;

    // Sérialiser la transaction en format JSON
    json toJson() const;

    void signTransaction(const string &privateKey);
};

#endif

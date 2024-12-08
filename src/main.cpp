#include <iostream>
#include <string>
#include <limits>
#include "Wallet.h"
#include "Transaction.h"
#include "Utils.h"
#include "WalletSecurity.h"

using namespace std;

void printMenu()
{
    cout << "\nMenu:\n";
    cout << "1. Générer une paire de clés\n";
    cout << "2. Créer une transaction\n";
    cout << "3. Sauvegarder la transaction\n";
    cout << "4. Afficher les informations de la transaction\n";
    cout << "5. Déchiffrer la clé privée\n";
    cout << "6. Quitter\n";
    cout << "Choisissez une option (1-6) : ";
}

int main()
{
    Wallet wallet;
    string toAddress;
    double amount;

    while (true)
    {
        printMenu();
        int choice;
        cin >> choice;

        switch (choice)
        {
        case 1:
            // Générer des clés
            wallet.generateKeys();
            break;

        case 2:
            // Créer une transaction
            cout << "Entrez l'adresse destinataire : ";
            cin >> toAddress;
            cout << "Entrez le montant à envoyer (BTC) : ";
            cin >> amount;
            wallet.createTransaction(toAddress, amount);
            break;

        case 3:
            // Sauvegarder la transaction
            wallet.savePrivateKey();
            break;

        case 4:
            // Afficher les informations de la transaction
            // Afficher les détails de la transaction ici
            break;

        case 5:
            // Déchiffrer la clé privée
            wallet.decryptPrivateKey(); // Appeler la fonction de déchiffrement
            break;

        case 6:
            // Quitter
            cout << "Au revoir!" << endl;
            return 0;

        default:
            cout << "Option invalide. Essayez encore." << endl;
            break;
        }
    }

    return 0;
}

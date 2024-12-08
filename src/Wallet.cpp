#include "Wallet.h"
#include "KeyGeneration.h"
#include "Transaction.h"
#include "WalletSecurity.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <filesystem>
#include <sys/stat.h>

using namespace std;
namespace fs = std::filesystem;

Wallet::Wallet()
{
    // Initialisation de l'adresse publique et privée
    privateKey = "";
    publicKey = "";
}

Wallet::~Wallet()
{
    // Nettoyage des ressources si nécessaire
}

// Fonction pour créer un dossier si nécessaire
void createDirectoryIfNotExists(const string &dir)
{
    // Obtenir le répertoire courant de l'exécutable
    fs::path executableDir = fs::current_path(); // Répertoire courant où l'exécutable est lancé
    fs::path targetDir = executableDir / dir;    // Chemin complet vers le dossier cible

    // Vérifier si le dossier existe déjà
    if (!fs::exists(targetDir))
    {
        // Créer le dossier si il n'existe pas
        if (fs::create_directory(targetDir))
        {
            cout << "Dossier '" << targetDir << "' créé avec succès." << endl;
        }
        else
        {
            cout << "Erreur lors de la création du dossier '" << targetDir << "'." << endl;
        }
    }
    else
    {
        cout << "Le dossier '" << targetDir << "' existe déjà." << endl;
    }
}

void Wallet::generateKeys()
{
    // Si le fichier de la clé privée n'existe pas, générer les clés
    KeyGeneration keyGen;
    keyGen.generateKeyPair(privateKey, publicKey);

    // Demander une passphrase et sécuriser la clé privée
    string passphrase = WalletSecurity::askForPassphrase();
    privateKey = WalletSecurity::securePrivateKey(privateKey, passphrase);

    // Sauvegarder la clé privée et publique dans des fichiers
    savePrivateKey();
    savePublicKey();

    cout << "Clé privée et publique générées et sauvegardées." << endl;
}

void Wallet::savePrivateKey()
{
    // Récupérer le répertoire de l'exécutable actuel
    fs::path executableDir = fs::current_path(); // Répertoire de l'exécutable

    // Construire le chemin vers le dossier WalletKeys dans ce répertoire
    fs::path folder = executableDir / "WalletKeys"; // Utilisation du répertoire courant pour le dossier WalletKeys

    // Créer le dossier WalletKeys s'il n'existe pas
    createDirectoryIfNotExists(folder.string());

    // Construire le chemin complet du fichier de la clé privée
    fs::path fullPath = folder / "privateKey.dat"; // Utilisation du répertoire courant pour le fichier de clé privée

    cout << "Chemin complet du fichier de clé privée : " << fullPath << endl; // Debug

    // Vérifier si le fichier existe déjà
    if (fs::exists(fullPath)) // Utiliser fs::exists pour une gestion des fichiers plus fiable
    {
        cout << "Le fichier '" << fullPath << "' existe déjà. La clé privée ne sera pas écrasée." << endl;
        return; // Ne pas écraser le fichier
    }

    // Si le fichier n'existe pas, on le crée et y écrit la clé privée
    ofstream outFile(fullPath, ios::out); // Utilisation de ios::out pour texte
    if (outFile.is_open())
    {
        outFile << privateKey; // Sauvegarder la clé privée
        outFile.close();
        cout << "Clé privée sauvegardée à " << fullPath << endl;
    }
    else
    {
        cout << "Erreur lors de l'ouverture du fichier pour sauvegarder la clé privée." << endl;
    }
}

void Wallet::decryptPrivateKey()
{
    try
    {
        // Étape 1 : Récupérer le répertoire de travail actuel
        fs::path currentDir = fs::current_path();

        // Étape 2 : Construire le chemin vers le dossier WalletKeys dans le répertoire courant
        fs::path folder = currentDir / "WalletKeys"; // Utiliser le répertoire courant pour "WalletKeys"
        fs::path encryptedFilePath = folder / "privateKey.dat";

        // Vérifier que le fichier chiffré existe
        if (!fs::exists(encryptedFilePath))
        {
            throw runtime_error("Erreur : Le fichier 'privateKey.dat' n'existe pas.");
        }

        // Étape 3 : Lire le contenu du fichier chiffré
        ifstream encryptedFile(encryptedFilePath, ios::in);
        if (!encryptedFile.is_open())
        {
            throw runtime_error("Erreur : Impossible d'ouvrir le fichier chiffré.");
        }

        string encryptedPrivateKey((istreambuf_iterator<char>(encryptedFile)),
                                   istreambuf_iterator<char>());
        encryptedFile.close();

        if (encryptedPrivateKey.empty())
        {
            throw runtime_error("Erreur : Le fichier chiffré est vide.");
        }

        // Étape 4 : Demander la passphrase à l'utilisateur
        string passphrase;
        cout << "Entrez votre passphrase composée de 12 mots pour déchiffrer votre clé : " << endl;
        passphrase = WalletSecurity::askForPassphrase();

        // Étape 5 : Déchiffrer la clé privée
        string decryptedPrivateKey = WalletSecurity::decryptPrivateKey(encryptedPrivateKey, passphrase);

        // Étape 6 : Construire le chemin vers le fichier déchiffré
        fs::path decryptedFilePath = folder / "privateKeyDecrypted.dat";

        // Écrire la clé privée déchiffrée dans le fichier
        ofstream decryptedFile(decryptedFilePath, ios::out | ios::trunc);
        if (!decryptedFile.is_open())
        {
            throw runtime_error("Erreur : Impossible de créer le fichier déchiffré.");
        }

        decryptedFile << decryptedPrivateKey;
        decryptedFile.close();

        cout << "Clé privée déchiffrée et écrite dans le fichier : " << decryptedFilePath << endl;
    }
    catch (const exception &e)
    {
        cerr << "Erreur : " << e.what() << endl;
    }
}

void Wallet::savePublicKey()
{
    // Récupérer le répertoire de l'exécutable actuel
    fs::path executableDir = fs::current_path(); // Répertoire de l'exécutable

    // Construire le chemin vers le dossier WalletKeys dans ce répertoire
    fs::path folder = executableDir / "WalletKeys"; // Utilisation du répertoire courant pour le dossier WalletKeys

    // Créer le dossier WalletKeys s'il n'existe pas
    createDirectoryIfNotExists(folder.string());

    // Construire le chemin complet du fichier de la clé publique
    fs::path fullPath = folder / "publicKey.dat"; // Utilisation du répertoire courant pour le fichier de clé publique

    cout << "Chemin complet du fichier de clé publique : " << fullPath << endl; // Debug

    // Vérifier si le fichier existe déjà
    if (fs::exists(fullPath)) // Utiliser fs::exists pour une gestion des fichiers plus fiable
    {
        cout << "Le fichier '" << fullPath << "' existe déjà. La clé publique ne sera pas écrasée." << endl;
        return; // Ne pas écraser le fichier
    }

    // Si le fichier n'existe pas, on le crée et y écrit la clé publique
    ofstream outFile(fullPath, ios::out); // Utilisation de ios::out pour texte
    if (outFile.is_open())
    {
        outFile << publicKey; // Sauvegarder la clé publique
        outFile.close();
        cout << "Clé publique sauvegardée à " << fullPath << endl;
    }
    else
    {
        cout << "Erreur lors de l'ouverture du fichier pour sauvegarder la clé publique." << endl;
    }
}

bool isValidAddress(const string &address)
{
    // Vérifier que l'adresse n'est pas vide
    if (address.empty())
    {
        return false;
    }

    // Vérifier la longueur de l'adresse (Bitcoin classique entre 26 et 35 caractères)
    if (address.length() < 26 || address.length() > 35)
    {
        return false;
    }

    // Vérification des caractères valides (caractères alphanumériques spécifiques)
    std::regex pattern("^[a-zA-Z0-9]{26,35}$");
    if (!std::regex_match(address, pattern))
    {
        return false;
    }

    // Vérifier si l'adresse commence par '1' (adresse P2PKH), '3' (adresse P2SH) ou 'bc1' (SegWit)
    if (address[0] == '1' || address[0] == '3' || address.substr(0, 3) == "bc1")
    {
        return true;
    }

    return false;
}

bool isValidAmount(double amount)
{
    return amount > 0;
}

void Wallet::createTransaction(const string &toAddress, double amount)
{
    // Vérification de la validité des données
    if (!isValidAddress(toAddress))
    {
        cout << "Erreur : Adresse de destination invalide." << endl;
        return;
    }

    if (!isValidAmount(amount))
    {
        cout << "Erreur : Montant de la transaction invalide." << endl;
        return;
    }
    // Créer une nouvelle transaction
    Transaction transaction(publicKey, toAddress, amount);

    // Signer la transaction avec la clé privée
    transaction.signTransaction(privateKey);

    // Sauvegarder la transaction dans un fichier
    string filename = "transactions.json"; // Nom du fichier de transaction
    transaction.saveToFile(filename);

    cout << "Transaction créée et signée pour " << amount << " BTC" << endl;
}

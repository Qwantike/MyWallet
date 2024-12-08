#include "Utils.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

using namespace std;

string hexToString(const string &hex)
{
    if (hex.length() % 2 != 0)
    {
        cerr << "Erreur : La chaîne hexadécimale doit avoir une longueur paire." << endl;
        return "";
    }

    string result = "";
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

string vectorToString(const vector<string> &vec)
{
    ostringstream resultStream;

    for (const auto &word : vec)
    {
        resultStream << word << " ";
    }

    string result = resultStream.str();

    // Supprimer l'espace final
    if (!result.empty() && result.back() == ' ')
    {
        result.pop_back();
    }

    return result;
}

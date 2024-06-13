#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>


using namespace std;
using namespace CryptoPP;

// Substitution cipher
string substitutionEncrypt(const string &plaintext) {
    string ciphertext = plaintext;
    for (char &c : ciphertext) {
        if (isalpha(c)) {
            c = ((c - 'a' + 3) % 26) + 'a'; // shift of 3
        }
    }
    return ciphertext;
}

string substitutionDecrypt(const string &ciphertext) {
    string plaintext = ciphertext;
    for (char &c : plaintext) {
        if (isalpha(c)) {
            c = ((c - 'a' - 3 + 26) % 26) + 'a'; //  shift of 3
        }
    }
    return plaintext;
}

// Transposition cipher
string transpositionEncrypt(const string &plaintext) {
    string ciphertext;
    int key = 2; // Example key
    for (int i = 0; i < key; ++i) {
        for (size_t j = i; j < plaintext.size(); j += key) {
            ciphertext.push_back(plaintext[j]);
        }
    }
    return ciphertext;
}

string transpositionDecrypt(const string &ciphertext) {
    string plaintext(ciphertext.size(), ' ');
    int key = 2; // Example key
    int index = 0;
    for (int i = 0; i < key; ++i) {
        for (size_t j = i; j < ciphertext.size(); j += key) {
            plaintext[j] = ciphertext[index++];
        }
    }
    return plaintext;
}

// AES encryption
string aesEncrypt(const string &plaintext, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE]) {
    string ciphertext;

    CBC_Mode<AES>::Encryption encryption(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(plaintext, true, new StreamTransformationFilter(encryption, new StringSink(ciphertext)));

    return ciphertext;
}

string aesDecrypt(const string &ciphertext, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE]) {
    string decryptedtext;

    CBC_Mode<AES>::Decryption decryption(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decryptedtext)));

    return decryptedtext;
}

int main() {
    cout << "Welcome to File Encryption/Decryption Program" << endl;

    while (true) {
        cout << "Choose an option:" << endl;
        cout << "1. Encrypt a file" << endl;
        cout << "2. Decrypt a file" << endl;
        cout << "3. Exit" << endl;
        cout << "Enter your choice: ";

        int choice;
        cin >> choice;

        if (choice == 1) {
            string filename;
            cout << "Enter the name of the file to encrypt: ";
            cin >> filename;

            ifstream inFile(filename);
            if (!inFile) {
                cerr << "Error: Unable to open file." << endl;
                continue;
            }

            string plaintext((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
            inFile.close();

            string ciphertext;

            // Encrypt using AES
            byte key[AES::DEFAULT_KEYLENGTH];
            byte iv[AES::BLOCKSIZE];
            memset(key, 0x00, AES::DEFAULT_KEYLENGTH);
            memset(iv, 0x00, AES::BLOCKSIZE);
            string aesCiphertext = aesEncrypt(plaintext, key, iv);

            // different encryption algorithms

            ofstream outFile(filename + ".enc");
            outFile << aesCiphertext;
            outFile.close();

            cout << "File encrypted successfully!" << endl;
        } else if (choice == 2) {
            string filename;
            cout << "Enter the name of the file to decrypt: ";
            cin >> filename;

            ifstream inFile(filename);
            if (!inFile) {
                cerr << "Error: Unable to open file." << endl;
                continue;
            }

            string ciphertext((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
            inFile.close();

            string decryptedtext;

            // Decrypt using AES
            byte key[AES::DEFAULT_KEYLENGTH];
            byte iv[AES::BLOCKSIZE];
            memset(key, 0x00, AES::DEFAULT_KEYLENGTH);
            memset(iv, 0x00, AES::BLOCKSIZE);
            string aesDecryptedtext = aesDecrypt(ciphertext, key, iv);

            //different decryption algorithms

            ofstream outFile(filename.substr(0, filename.size() - 4)); // Remove .enc extension
            outFile << aesDecryptedtext;
            outFile.close();

            cout << "File decrypted successfully!" << endl;
        } else if (choice == 3) {
            cout << "Exiting program. Goodbye!" << endl;
            break;
        } else {
            cout << "Invalid choice. Please enter a valid option." << endl;
        }
    }

    return 0;
}
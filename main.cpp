#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cstring>
#include <bitset>
using namespace std;

class SHA1 {
private:
    uint32_t state[5];
    uint64_t totalLength;
    unsigned char buffer[64];
    size_t bufferIndex;
    static inline uint32_t rotateLeft(uint32_t value, size_t bits) { return (value << bits) | (value >> (32 - bits)); }
    void processBlock(const unsigned char* block) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | (block[i * 4 + 3]);
        for (int i = 16; i < 80; i++) w[i] = rotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotateLeft(b, 30); b = a; a = temp;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
    }
public:
    SHA1() { reset(); }
    void reset() { state[0] = 0x67452301; state[1] = 0xEFCDAB89; state[2] = 0x98BADCFE; state[3] = 0x10325476; state[4] = 0xC3D2E1F0; totalLength = 0; bufferIndex = 0; }
    void update(const void* data, size_t length) {
        const unsigned char* input = reinterpret_cast<const unsigned char*>(data);
        totalLength += length;
        if (bufferIndex > 0) {
            while (bufferIndex < 64 && length > 0) buffer[bufferIndex++] = *input++, length--;
            if (bufferIndex == 64) processBlock(buffer), bufferIndex = 0;
        }
        while (length >= 64) processBlock(input), input += 64, length -= 64;
        while (length > 0) buffer[bufferIndex++] = *input++, length--;
    }
    std::string finalize() {
        unsigned char finalBlock[64];
        size_t paddingLength = 64 - ((totalLength + 9) % 64);
        if (paddingLength < 8) paddingLength += 64;
        memcpy(finalBlock, buffer, bufferIndex);
        finalBlock[bufferIndex] = 0x80;
        memset(finalBlock + bufferIndex + 1, 0, paddingLength - 1);
        uint64_t bitLength = totalLength * 8;
        for (int i = 0; i < 8; i++) finalBlock[paddingLength + i] = (bitLength >> (56 - i * 8)) & 0xFF;
        processBlock(finalBlock);
        if (paddingLength > 64 - 9) memset(finalBlock, 0, 56), memcpy(finalBlock + 56, finalBlock + paddingLength + bufferIndex + 1, 8), processBlock(finalBlock);
        std::stringstream ss;
        for (int i = 0; i < 5; i++) ss << std::hex << std::setfill('0') << std::setw(8) << state[i];
        return ss.str();
    }
    static std::string hashFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open file: " + filename);
        SHA1 sha1;
        char buffer[4096];
        while (file) file.read(buffer, sizeof(buffer)), sha1.update(buffer, file.gcount());
        return sha1.finalize();
    }
};

int IP[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
int FP[64] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
int E[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
int PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
int PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
int S[8][4][16] = { /*S-box values*/ };
int P[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

vector<bool> xorOperation(const vector<bool> &a, const vector<bool> &b) {
    vector<bool> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) result[i] = a[i] ^ b[i];
    return result;
}

vector<bool> bytesToBits(const vector<unsigned char> &bytes) {
    vector<bool> bits;
    for (unsigned char byte : bytes) for (int i = 7; i >= 0; --i) bits.push_back((byte >> i) & 1);
    return bits;
}

vector<unsigned char> bitsToBytes(const vector<bool> &bits) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < bits.size(); i += 8) {
        unsigned char byte = 0;
        for (int j = 0; j < 8; ++j) byte = (byte << 1) | bits[i + j];
        bytes.push_back(byte);
    }
    return bytes;
}

vector<unsigned char> readFile(const string &filename) {
    ifstream file(filename, ios::binary);
    vector<unsigned char> data((istreambuf_iterator<char>(file)), {});
    return data;
}

void writeFile(const string &filename, const vector<unsigned char> &data) {
    ofstream file(filename, ios::binary);
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
}

vector<unsigned char> padData(const vector<unsigned char> &data) {
    size_t paddingSize = 8 - (data.size() % 8);
    vector<unsigned char> paddedData(data);
    paddedData.insert(paddedData.end(), paddingSize, static_cast<unsigned char>(paddingSize));
    return paddedData;
}

vector<bool> permute(const vector<bool> &input, const int *table, int size) {
    vector<bool> output(size);
    for (int i = 0; i < size; ++i) output[i] = input[table[i] - 1];
    return output;
}

vector<vector<bool>> generateKeys(const vector<bool> &key) {
    vector<vector<bool>> roundKeys(16, vector<bool>(48));
    vector<bool> permutedKey = permute(key, PC1, 56);
    vector<bool> C(permutedKey.begin(), permutedKey.begin() + 28);
    vector<bool> D(permutedKey.begin() + 28, permutedKey.end());
    for (int i = 0; i < 16; ++i) {
        int shiftAmount = SHIFTS[i];
        rotate(C.begin(), C.begin() + shiftAmount, C.end());
        rotate(D.begin(), D.begin() + shiftAmount, D.end());
        vector<bool> combined = C;
        combined.insert(combined.end(), D.begin(), D.end());
        roundKeys[i] = permute(combined, PC2, 48);
    }
    return roundKeys;
}

vector<bool> desFunction(const vector<bool> &right, const vector<bool> &key) {
    vector<bool> expanded = permute(right, E, 48);
    vector<bool> xorResult = xorOperation(expanded, key);
    vector<bool> sBoxOutput(32);
    for (int i = 0; i < 8; ++i) {
        int row = (xorResult[i * 6] << 1) | xorResult[i * 6 + 5];
        int col = (xorResult[i * 6 + 1] << 3) | (xorResult[i * 6 + 2] << 2) | (xorResult[i * 6 + 3] << 1) | xorResult[i * 6 + 4];
        int sValue = S[i][row][col];
        for (int j = 0; j < 4; ++j) sBoxOutput[i * 4 + j] = (sValue >> (3 - j)) & 1;
    }
    return permute(sBoxOutput, P, 32);
}

vector<bool> desEncrypt(const vector<bool> &input, const vector<vector<bool>> &keys) {
    vector<bool> permutedInput = permute(input, IP, 64);
    vector<bool> left(permutedInput.begin(), permutedInput.begin() + 32);
    vector<bool> right(permutedInput.begin() + 32, permutedInput.end());
    for (int i = 0; i < 16; ++i) {
        vector<bool> temp = right;
        right = xorOperation(left, desFunction(right, keys[i]));
        left = temp;
    }
    vector<bool> combined = right;
    combined.insert(combined.end(), left.begin(), left.end());
    return permute(combined, FP, 64);
}

vector<bool> desDecrypt(const vector<bool> &input, const vector<vector<bool>> &keys) {
    return desEncrypt(input, vector<vector<bool>>(keys.rbegin(), keys.rend()));
}

void desCBCEncrypt(const string &inputFile, const string &outputFile, const vector<bool> &key, const vector<bool> &iv) {
    vector<unsigned char> plaintextData = readFile(inputFile);
    vector<unsigned char> paddedData = padData(plaintextData);
    vector<bool> bits = bytesToBits(paddedData);
    vector<vector<bool>> keys = generateKeys(key);
    vector<bool> ciphertextBits;
    vector<bool> previousCiphertext = iv;
    for (size_t i = 0; i < bits.size(); i += 64) {
        vector<bool> block(bits.begin() + i, bits.begin() + min(i + 64, bits.size()));
        block = xorOperation(block, previousCiphertext);
        vector<bool> encryptedBlock = desEncrypt(block, keys);
        ciphertextBits.insert(ciphertextBits.end(), encryptedBlock.begin(), encryptedBlock.end());
        previousCiphertext = encryptedBlock;
    }
    vector<unsigned char> ciphertextBytes = bitsToBytes(ciphertextBits);
    writeFile(outputFile, ciphertextBytes);
}

void desCBCDecrypt(const string &inputFile, const string &outputFile, const vector<bool> &key, const vector<bool> &iv) {
    vector<unsigned char> ciphertextData = readFile(inputFile);
    vector<bool> bits = bytesToBits(ciphertextData);
    vector<vector<bool>> keys = generateKeys(key);
    vector<bool> plaintextBits;
    vector<bool> previousCiphertext = iv;
    for (size_t i = 0; i < bits.size(); i += 64) {
        vector<bool> block(bits.begin() + i, bits.begin() + min(i + 64, bits.size()));
        vector<bool> decryptedBlock = desDecrypt(block, keys);
        vector<bool> originalBlock = xorOperation(decryptedBlock, previousCiphertext);
        plaintextBits.insert(plaintextBits.end(), originalBlock.begin(), originalBlock.end());
        previousCiphertext = block;
    }
    vector<unsigned char> plaintextBytes = bitsToBytes(plaintextBits);
    size_t paddingSize = plaintextBytes.back();
    plaintextBytes.resize(plaintextBytes.size() - paddingSize);
    writeFile(outputFile, plaintextBytes);
}

void random_filecreation(int fileSize, string fileName){
    ofstream MyFile(fileName);
    for(int i = 0; i < fileSize; i++){
        MyFile << rand()%2;
    }
    MyFile.close();
}

int main() {
    string inputFile = "input.txt";
    string encryptedFile = "ciphertext.bin";
    string decryptedFile = "decrypted.txt";
    unsigned long long key = 0x133457799BBCDFF1;
    vector<bool> iv(64);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, 1);
    for (int i = 0; i < 64; ++i) iv[i] = dist(gen);
    vector<bool> keyBits(64);
    for (int i = 0; i < 64; ++i) keyBits[i] = (key >> (63 - i)) & 1;

    random_filecreation(1024*1024, "input.txt");

    string originalHash = SHA1::hashFile(inputFile);
    cout << "Original SHA-1 Hash: " << originalHash << endl;

    desCBCEncrypt(inputFile, encryptedFile, keyBits, iv);
    desCBCDecrypt(encryptedFile, decryptedFile, keyBits, iv);

    string decryptedHash = SHA1::hashFile(decryptedFile);
    cout << "Decrypted SHA-1 Hash: " << decryptedHash << endl;

    if (originalHash == decryptedHash) cout << "Success: SHA-1 hashes match!" << endl;
    else cout << "Error: SHA-1 hashes do not match!" << endl;

    return 0;
}

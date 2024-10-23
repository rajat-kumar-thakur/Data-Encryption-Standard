#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace std;

class SHA1 {
private:
    uint32_t state[5];
    uint64_t totalLength;
    unsigned char buffer[64];
    size_t bufferIndex;

    static inline uint32_t rotateLeft(uint32_t value, size_t bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    void processBlock(const unsigned char* block) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) |
                   (block[i * 4 + 1] << 16) |
                   (block[i * 4 + 2] << 8) |
                   (block[i * 4 + 3]);
        }

        for (int i = 16; i < 80; i++) {
            w[i] = rotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];

        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

public:
    SHA1() {
        reset();
    }

    void reset() {
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
        totalLength = 0;
        bufferIndex = 0;
    }

    void update(const void* data, size_t length) {
        const unsigned char* input = reinterpret_cast<const unsigned char*>(data);
        totalLength += length;

        if (bufferIndex > 0) {
            while (bufferIndex < 64 && length > 0) {
                buffer[bufferIndex++] = *input++;
                length--;
            }
            if (bufferIndex == 64) {
                processBlock(buffer);
                bufferIndex = 0;
            }
        }

        while (length >= 64) {
            processBlock(input);
            input += 64;
            length -= 64;
        }

        while (length > 0) {
            buffer[bufferIndex++] = *input++;
            length--;
        }
    }

    std::string finalize() {
        unsigned char finalBlock[64];
        size_t paddingLength = 64 - ((totalLength + 9) % 64);
        if (paddingLength < 8) paddingLength += 64;

        memcpy(finalBlock, buffer, bufferIndex);
        finalBlock[bufferIndex] = 0x80;
        memset(finalBlock + bufferIndex + 1, 0, paddingLength - 1);

        uint64_t bitLength = totalLength * 8;
        for (int i = 0; i < 8; i++) {
            finalBlock[paddingLength + i] = (bitLength >> (56 - i * 8)) & 0xFF;
        }

        processBlock(finalBlock);
        if (paddingLength > 64 - 9) {
            memset(finalBlock, 0, 56);
            memcpy(finalBlock + 56, finalBlock + paddingLength + bufferIndex + 1, 8);
            processBlock(finalBlock);
        }

        std::stringstream ss;
        for (int i = 0; i < 5; i++) {
            ss << std::hex << std::setfill('0') << std::setw(8) << state[i];
        }

        return ss.str();
    }

    static std::string hash(const std::string& input) {
        SHA1 sha1;
        sha1.update(input.c_str(), input.length());
        return sha1.finalize();
    }

    static std::string hashFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + filename);
        }

        SHA1 sha1;
        char buffer[4096];
        while (file) {
            file.read(buffer, sizeof(buffer));
            sha1.update(buffer, file.gcount());
        }

        return sha1.finalize();
    }
};


void random_filecreation(int fileSize, string fileName){
    ofstream MyFile(fileName);
    for(int i = 0; i < fileSize; i++){
        MyFile << rand()%2;
    }
    MyFile.close();
}

int main(){
    //random_filecreation(1024*1024, "message.txt");
    string fileHash = SHA1::hashFile("message.txt");
    cout << "SHA-1 hash: " << fileHash << endl;
    
    return 0;
}
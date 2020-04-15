#include <fstream>
#include <cstdint>
#include <iostream>
#include <vector>
#include <cstring>

struct MsgHeader
{
    uint16_t size_;      //Packet size
    uint8_t key_;        //Key used as seed for enc/dec
    uint8_t hash_;       //Hash generated to validate the process
    int16_t code_;       //Internal packet identifier
    int16_t index_;      //Index from the user that sent the packet
    uint32_t timestamp_; //Timestamp usually get right before starting the enc/dec process
};

using namespace std;

uint8_t keys[512];
size_t encryptedFileSize;
uint8_t *encryptedFileRaw;
vector<MsgHeader *> encryptedPackets;
size_t decryptedFileSize;
uint8_t *decryptedFileRaw;
vector<MsgHeader *> decryptedPackets;

void encrypt()
{
    size_t pos = 0;
    for (auto packet : decryptedPackets)
    {
        uint8_t *ptr = reinterpret_cast<uint8_t *>(packet);
        uint16_t j = 4;
        int key = (uint8_t)keys[packet->key_ << 1];
        char cmp_enc = 0, cmp_dec = 0;
        do
        {
            uint32_t mappedKey = keys[((key % 256) << 1) + 1];
            switch (j & 3)
            {
            case 0:
                ptr[j] = ptr[j] + (uint32_t)(mappedKey << 1);
                break;
            case 1:
                ptr[j] = ptr[j] - (uint32_t)(mappedKey >> 3);
                break;
            case 2:
                ptr[j] = ptr[j] + (uint32_t)(mappedKey << 2);
                break;
            case 3:
                ptr[j] = ptr[j] - (uint32_t)(mappedKey >> 5);
                break;
            }
            j++;
            key++;
        } while (j < packet->size_);
    }
}

void decrypt()
{
    size_t pos = 0;
    for (auto packet : encryptedPackets)
    {
        uint8_t *ptr = reinterpret_cast<uint8_t *>(packet);
        uint16_t j = 4;
        int key = (uint8_t)keys[packet->key_ << 1];
        char cmp_enc = 0, cmp_dec = 0;
        do
        {
            uint32_t mappedKey = keys[((key % 256) << 1) + 1];
            switch (j & 3)
            {
            case 0:
                ptr[j] = ptr[j] - (uint32_t)(mappedKey << 1);
                break;
            case 1:
                ptr[j] = ptr[j] + (uint32_t)((int32_t)mappedKey >> 3);
                break;
            case 2:
                ptr[j] = ptr[j] - (uint32_t)(mappedKey << 2);
                break;
            case 3:
                ptr[j] = ptr[j] + (uint32_t)((int32_t)mappedKey >> 5);
                break;
            }
            j++;
            key++;
        } while (j < packet->size_);
    }
}

int readKeys(char *filePath)
{
    fstream file(filePath, file.binary | file.in);
    if (!file.is_open())
    {
        cout << "Failed to open the keys file" << endl;
        return -1;
    }
    file.read(reinterpret_cast<char *>(keys), sizeof(keys));
    file.close();
    return 0;
}

uint8_t *readDataFile(char *filePath, vector<MsgHeader *> &packets, size_t &fileSize)
{
    fstream file(filePath, file.binary | file.in);
    if (!file.is_open())
    {
        cout << "Failed to open the keys file" << endl;
        return 0;
    }
    file.seekg(0, file.end);
    fileSize = file.tellg();
    file.seekg(0);

    uint8_t *dataRaw = new uint8_t[fileSize];
    file.read(reinterpret_cast<char *>(dataRaw), fileSize);
    file.close();

    uint8_t *ptr = dataRaw;
    size_t tmpSize = fileSize;
    while (tmpSize > 0)
    {
        MsgHeader *packet = reinterpret_cast<MsgHeader *>(ptr);
        packets.push_back(packet);
        ptr += packet->size_;
        tmpSize -= packet->size_;
    }
    return dataRaw;
}

int main(int argc, char **argv)
{
    int ret;
    if ((ret = readKeys(argv[1])))
    {
        return ret;
    }
    if ((encryptedFileRaw = readDataFile(argv[3], encryptedPackets, encryptedFileSize)) == 0)
    {
        return ret;
    }
    if ((decryptedFileRaw = readDataFile(argv[4], decryptedPackets, decryptedFileSize)) == 0)
    {
        return ret;
    }
    string op = argv[2];
    if (op == "enc")
    {
        encrypt();
        fstream out("./encoded.bin", out.binary | out.out);
        out.write(reinterpret_cast<char *>(decryptedFileRaw), decryptedFileSize);
        out.close();
    }
    if (op == "dec")
    {
        decrypt();
        fstream out("./decoded.bin", out.binary | out.out);
        out.write(reinterpret_cast<char *>(encryptedFileRaw), encryptedFileSize);
        out.close();
    }
    int diff = 0;
    for (int i = 0; i < encryptedFileSize; i++)
    {
        diff += encryptedFileRaw[i] != decryptedFileRaw[i];
    }

    cout << diff << " differences";

    return diff;
}
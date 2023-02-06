const keys = new Uint8Array(512);
let sizeDecryptedFile;
let decryptedFileRaw;
const decryptedPackets = [];

function encrypt() {
    for (const packet of decryptedPackets) {
        const ptr = new Uint8Array(packet.buffer);
        let j = 4;
        let key = keys[packet.key_ << 1];
        do {
            const mappedKey = keys[((key % 256) << 1) + 1];
            switch (j & 3) {
                case 0:
                    ptr[j] = ptr[j] + (mappedKey << 1);
                    break;
                case 1:
                    ptr[j] = ptr[j] - (mappedKey >> 3);
                    break;
                case 2:
                    ptr[j] = ptr[j] + (mappedKey << 2);
                    break;
                case 3:
                    ptr[j] = ptr[j] - (mappedKey >> 5);
                    break;
            }
            j++;
            key++;
        } while (j < packet.size_);
    }
}

async function readKeys(filePath) {
    const response = await fetch(filePath);
    const buffer = await response.arrayBuffer();
    keys.set(new Uint8Array(buffer));
    return true;
}

async function readDataFile(filePath, packets, fileSize) {
    const response = await fetch(filePath);
    const buffer = await response.arrayBuffer();
    fileSize = buffer.byteLength;
    const dataRaw = new Uint8Array(buffer);

    let ptr = dataRaw;
    let tmpSize = fileSize;
    while (tmpSize > 0) {
        const packet = new DataView(ptr.buffer, ptr.byteOffset, tmpSize);
        packets.push(packet);
        ptr = new Uint8Array(ptr.buffer, ptr.byteOffset + packet.getUint16(0, true));
        tmpSize -= packet.getUint16(0, true);
    }
    return dataRaw;
}

async function main(filePath) {
    const ret = await readKeys(filePath);
    decryptedFileRaw = await readDataFile("./decoded.bin", decryptedPackets, sizeDecryptedFile);
    encrypt();
}

main(process.argv[2]);

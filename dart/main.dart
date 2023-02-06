import 'dart:typed_data';
import 'dart:io';
import 'dart:math';

class MsgHeader {
  int size;
  int key;
  int hash;
  int code;
  int index;
  int timestamp;
}

List<int> keys = List<int>(512);
int sizeDecryptedFile;
Uint8List decryptedFileRaw;
List<MsgHeader> decryptedPackets = List<MsgHeader>();

void encrypt() {
  for (var packet in decryptedPackets) {
    var j = 4;
    int key = keys[packet.key << 1];
    do {
      var mappedKey = keys[((key % 256) << 1) + 1];
      switch (j & 3) {
        case 0:
          packet.hash += (mappedKey << 1);
          break;
        case 1:
          packet.hash -= (mappedKey >> 3);
          break;
        case 2:
          packet.hash += (mappedKey << 2);
          break;
        case 3:
          packet.hash -= (mappedKey >> 5);
          break;
      }
      j++;
      key++;
    } while (j < packet.size);
  }
}

Future<bool> readKeys(String filePath) async {
  var file = File(filePath);
  if (!await file.exists()) {
    print("Failed to open the keys file");
    return false;
  }
  var keysList = await file.readAsBytes();
  for (var i = 0; i < keysList.length; i++) {
    keys[i] = keysList[i];
  }
  return true;
}

Future<Uint8List> readDataFile(String filePath) async {
  var file = File(filePath);
  if (!await file.exists()) {
    print("Failed to open the keys file");
    return null;
  }
  var dataRaw = await file.readAsBytes();
  var ptr = 0;
  var tmpSize = dataRaw.length;
  while (tmpSize > 0) {
    var packet = MsgHeader();
    packet.size = dataRaw[ptr];
    ptr += packet.size;
    decryptedPackets.add(packet);
    tmpSize -= packet.size;
  }
  return Uint8List.fromList(dataRaw);
}

Future<void> main(List<String> args) async {
  var ret = await readKeys(args[0]);
  decryptedFileRaw = await readDataFile('./decoded.bin');
  encrypt();
  var file = File('./encoded.bin');
  await file.writeAsBytes(decryptedFileRaw);
}

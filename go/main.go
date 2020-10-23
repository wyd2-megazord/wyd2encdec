package main

import (
	"fmt"
	"os"
	"unsafe"
)

//MsgHeader defines the basic struct for a WYD2 packet header
type MsgHeader struct {
	size      uint16 //Packet size
	key       uint8  //Key used as seed for enc/dec
	hash      uint8  //Hash generated to validate the process
	code      int16  //Internal packet identifier
	index     int16  //Index from the user that sent the packet
	timestamp uint32 //Timestamp usually get right before starting the enc/dec process
}

var (
	keys              []uint8 = make([]uint8, 512)
	sizeEncryptedFile int64
	encryptedFileRaw  *[]uint8     //[sizeEncryptedFile]uint8
	encryptedPackets  []*MsgHeader = []*MsgHeader{}
	sizeDecryptedFile int64
	decryptedFileRaw  *[]uint8     //[sizeDecryptedFile]uint8
	decryptedPackets  []*MsgHeader = []*MsgHeader{}
)

func encrypt() {
    for _, packet := range decryptedPackets {
		ptr := unsafe.Pointer(packet)
        j := uint16(4)
        key := int(uint8(keys[uint16(packet.key) << 1]))
        for ; j < packet.size; j++ {
			mappedKey := uint32(keys[(uint16(key % 256) << 1) + 1])
			currPtr := unsafe.Pointer(uintptr(ptr) + uintptr(j))
            switch j & 3 {
				case 0:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) + uint32(mappedKey << 1))
				case 1:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) - uint32(mappedKey >> 3))
				case 2:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) + uint32(mappedKey << 2))
				case 3:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) - uint32(mappedKey >> 5))
			}
			key++;
        }
    }
}

func decrypt() {
    for _, packet := range encryptedPackets {
		ptr := unsafe.Pointer(packet)
        j := uint16(4)
        key := int(uint8(keys[uint16(packet.key) << 1]))
        for ; j < packet.size; j++ {
			mappedKey := uint32(keys[(uint16(key % 256) << 1) + 1])
			currPtr := unsafe.Pointer(uintptr(ptr) + uintptr(j))
            switch j & 3 {
				case 0:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) - uint32(mappedKey << 1))
				case 1:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) + uint32(mappedKey >> 3))
				case 2:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) - uint32(mappedKey << 2))
				case 3:
					*(*uint8)(currPtr) = uint8(uint32(*(*uint8)(currPtr)) + uint32(mappedKey >> 5))
			}
			key++;
        }
    }
}

func readKeys(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Failed to open the keys file")
		fmt.Println(err, filePath)
		return false
	}
	defer f.Close()
	count, err := f.Read(keys)
	if err != nil || count < 512 {
		fmt.Println("Failed to read the keys file")
		return false
	}
	return true
}

func readDataFile(filePath string, packets *[]*MsgHeader, fileSize *int64) *[]uint8 {
	fileInfo, _ := os.Stat(filePath)
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Failed to open the data file")
		return nil
	}
	defer f.Close()
	*fileSize = fileInfo.Size()

	dataRaw := make([]uint8, *fileSize)
	count, err := f.Read(dataRaw)
	i := 0
	for i < count {
		packet := (*MsgHeader)(unsafe.Pointer(&dataRaw[i]))
		*packets = append(*packets, packet)
		i += int(packet.size)
	}

	return &dataRaw
}

func main() {
	if len(os.Args) < 5 {
		fmt.Println("Not enough arguments")
		os.Exit(-1)
	}
	if readKeys(os.Args[1]) == false {
		os.Exit(-2)
	}
	encryptedFileRaw = readDataFile(os.Args[3], &encryptedPackets, &sizeEncryptedFile)
	if encryptedFileRaw == nil {
		os.Exit(-3)
	}
	decryptedFileRaw = readDataFile(os.Args[4], &decryptedPackets, &sizeDecryptedFile)
	if decryptedFileRaw == nil {
		os.Exit(-4)
	}
	op := os.Args[2]
	var out *os.File
	if op == "enc" {
		encrypt()
		out, _ = os.Create("./encoded.bin")
		out.Write(*decryptedFileRaw)
	}
	if op == "dec" {
		decrypt()
		out, _ = os.Create("./decoded.bin")
		out.Write(*encryptedFileRaw)
	}
	defer out.Close()
	diff := 0
	for i := int64(0); i < sizeEncryptedFile; i++ {
		if (*encryptedFileRaw)[i] != (*decryptedFileRaw)[i] {
			diff++
		}
	}
	fmt.Println(diff, "differences")
}

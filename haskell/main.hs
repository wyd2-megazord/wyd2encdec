import System.IO
import Data.Vector (Vector, fromList)
import Data.Word
import Data.Int
import Data.Bits

data MsgHeader = MsgHeader {
    size_ :: Word16,
    key_ :: Word8,
    hash_ :: Word8,
    code_ :: Int16,
    index_ :: Int16,
    timestamp_ :: Word32
} deriving (Show)

keys :: Vector Word16
keys = fromList $ fmap to16BitKey [0..511]
  where to16BitKey n = fromIntegral n + fromIntegral n + 1

decryptedPackets :: [MsgHeader]
decryptedPackets = []

encrypt :: [MsgHeader] -> [MsgHeader]
encrypt decryptedPackets = map (\(i, packet) -> packet {
    size_ = (encrypt' (key_ packet) (size_ packet) i),
    key_ = key_ packet,
    hash_ = hash_ packet,
    code_ = code_ packet,
    index_ = index_ packet,
    timestamp_ = timestamp_ packet
}) (zip [0..] decryptedPackets)
  where encrypt' key size i =
          foldl (\s j -> s + fromIntegral (mappedKey .&. (1 `shiftL` (j .&. 3)))) size [4..size - 1]
          where mappedKey = keys ! ((key `mod` 256) * 2 + 1)

readKeys :: FilePath -> IO (Either String (Vector Word16))
readKeys filePath = do
    handle <- openBinaryFile filePath ReadMode
    contents <- hGetContents handle
    return $ Right $ fromList $ fmap (\w -> fromIntegral w) (map fromIntegral (take 512 contents))

readDataFile :: FilePath -> IO (Either String [MsgHeader])
readDataFile filePath = do
    handle <- openBinaryFile filePath ReadMode
    contents <- hGetContents handle
    return $ Right $ parseContents contents
  where parseContents contents =
          fst $ foldl (\(acc, curr) size ->
            let header = MsgHeader {
              size_ = size,
              key_ = fromIntegral $ contents !! (curr + 2),
              hash_ = fromIntegral $ contents !! (curr + 3),
              code_ = fromIntegral (contents !! (curr + 4)) .|. (fromIntegral (contents !! (curr + 5)) `shiftL` 8),
              index_ = fromIntegral (contents !! (curr + 6)) .|. (fromIntegral (contents !! (curr + 7)) `shiftL` 8),
              timestamp_ = fromIntegral (contents !! (curr + 8)) .|. (fromIntegral (contents !! (curr + 9)) `shiftL` 8) .|. (fromIntegral (contents !! (curr + 10)) `shiftL` 16) .|. (fromIntegral (contents !! (curr + 11)) `shiftL` 24)
            }
            in (acc ++ [header], curr + fromIntegral size)
          ) ([], 0) (fmap fromIntegral (takeWhile (/= 0)

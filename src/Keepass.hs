module Keepass where

import qualified Data.ByteString as BS
import qualified Data.Binary.Strict.Get as BG

import Data.Bits
import Data.Word

import Control.Applicative
import Control.Monad

type KPassword = String

type KEntry = (String, String)
data KMeta = KMeta deriving (Show)
data KDBUnlocked = KDBUnlocked KMeta [KEntry] deriving (Show)

type KDBLength = Int
type KBody = BS.ByteString
data KDBLocked = KDBLocked KDBLength KHeader KBody deriving (Show)

data KHeader = KHeader {
    getFlags :: Word32
  , getVer :: Word32
  , getSeedRand :: BS.ByteString
  , getEncIv :: BS.ByteString
  , getNGroups :: Word32
  , getNEntries :: Word32
  , getChecksum :: BS.ByteString
  , getSeedKey :: BS.ByteString
  , getSeedRotN :: Word32
} deriving (Show)

type ParseEither a = Either String a

loadKdb :: BS.ByteString -> ParseEither KDBLocked
loadKdb content = do
    let (header, body) = BS.splitAt kdbHeaderSize content
    header' <- parseHeader header
    return $ KDBLocked (BS.length content) header' body

-- file format
kdbHeaderSize :: Int
kdbHeaderSize = 124

kdbSig1, kdbSig2v1, kdbSig2v2, kdbVerDw, kdbFlagRijndael :: Word32
kdbSig1   = 0x9AA2D903
kdbSig2v1 = 0xB54BFB65
kdbSig2v2 = 0xB54BFB67
kdbVerDw  = 0x00030002
kdbFlagRijndael  = 2

parseHeader :: BS.ByteString -> ParseEither KHeader
parseHeader header = do
    when (BS.length header < kdbHeaderSize) $
        fail "truncated header"

    let (result, header') = BG.runGet readMagicNumber header
    (magic1, magic2) <- result

    unless (magic1 == kdbSig1 && magic2 == kdbSig2v1) $
        fail "Not a KeePassX file"

    kheader <- fst $ BG.runGet readHeader header'

    unless ((getVer kheader `xor` kdbVerDw) .&. 0xffffff00 == 0) $
        fail "wrong DB_VER_DW"

    when (getFlags kheader .&. kdbFlagRijndael == 0) $
        fail $ "unsupported encryption: " ++ show (getFlags kheader)

    return kheader

readMagicNumber :: BG.Get (Word32, Word32)
readMagicNumber = liftM2 (,) BG.getWord32le BG.getWord32le

readHeader :: BG.Get KHeader
readHeader = KHeader <$>
             BG.getWord32le <*> -- flags
             BG.getWord32le <*> -- ver
             BG.getByteString 16 <*> -- seed_rand
             BG.getByteString 16 <*> -- enc_iv
             BG.getWord32le <*> -- n_groups
             BG.getWord32le <*> -- n_entries
             BG.getByteString 32 <*> -- checksum
             BG.getByteString 32 <*> -- seed_key
             BG.getWord32le -- seed_rot_n

-- decoding
decode :: KDBLocked -> KPassword -> Either String KDBUnlocked
decode kdb password = Right $ KDBUnlocked KMeta []

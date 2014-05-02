module Keepass where

import qualified Data.ByteString as BS
import qualified Data.Binary.Strict.Get as BG
import Data.Word
import Control.Monad

type KEntry = (String, String)
data KMeta = KMeta deriving (Show)
data KDBUnlocked = KDBUnlocked KMeta [KEntry] deriving (Show)

data KHeader = KHeader String deriving (Show)
type KBody = BS.ByteString
data KDBLocked = KDBLocked KHeader KBody deriving (Show)

type ParseEither a = Either String a

loadKdb :: BS.ByteString -> ParseEither KDBLocked
loadKdb content = do
    let (header, body) = BS.splitAt kdbHeaderSize content
    header' <- parseHeader header
    return $ KDBLocked header' body

-- file format
kdbHeaderSize :: Int
kdbHeaderSize = 124

kdbSig1, kdbSig2v1, kdbSig2v2, kdbVerDw :: Word32
kdbSig1   = 0x9AA2D903
kdbSig2v1 = 0xB54BFB65
kdbSig2v2 = 0xB54BFB67
kdbVerDw  = 0x00030002

parseHeader :: BS.ByteString -> ParseEither KHeader
parseHeader header = do
    let (result, header') = BG.runGet readMagicNumber header
    (magic1, magic2) <- result
    if (magic1 == kdbSig1) && (magic2 == kdbSig2v1) then
        return $ KHeader ""
        else fail "Not a KeePassX file"

readMagicNumber :: BG.Get (Word32, Word32)
readMagicNumber = liftM2 (,) BG.getWord32le BG.getWord32le

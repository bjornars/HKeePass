module Keepass where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.Binary.Strict.Get as BG

import Data.Bits
import Data.Char
import Data.List hiding (group)
import Data.Word

import Control.Applicative
import Control.Monad

import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Hash.SHA256 as SHA

type KPassword = String

data KDBUnlocked = KDBUnlocked [KGroup] [KEntry] deriving (Show)

type KEntry = [KEntryLine]
data KEntryLine =
    KEGroupId Int
    | KETitle String
    | KEUrl String
    | KEUsername String
    | KEPassword String
    | KEComment String
    deriving (Show)

type KGroup = [KGroupLine]
data KGroupLine = KGID Int | KGTitle String deriving (Show)

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

loadKdb :: BS.ByteString -> Either String KDBLocked
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

parseHeader :: BS.ByteString -> Either String KHeader
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
readHeader =
    KHeader <$>
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
decode (KDBLocked _ kheader body) password =
    let decrypted = tafse kheader body password in
    if SHA.hash decrypted == getChecksum kheader then
        parse kheader decrypted
    else
        Left "wrong password"

tafse :: KHeader -> BS.ByteString -> KPassword -> BS.ByteString
tafse kheader body password = unpad paddedBody
    where cipher = AES.initAES $ getSeedKey kheader
          pre_key = SHA.hash $ C8.pack password
          iterations = fromIntegral (getSeedRotN kheader) :: Int
          key = iterate (AES.encryptECB cipher) pre_key !! iterations
          key2 = SHA.hash key
          key3 = SHA.hash $ getSeedRand kheader `BS.append` key2
          cipher2 = AES.initAES key3
          paddedBody = AES.decryptCBC cipher2 (getEncIv kheader) body
          unpad xs = BS.take (BS.length xs - fromIntegral (BS.last xs)) xs

parse :: KHeader -> BS.ByteString -> Either String KDBUnlocked
parse kheader body =
    let ngroups = fromIntegral $ getNGroups kheader
        nentries = fromIntegral $ getNEntries kheader
        (groups, body') = BG.runGet (parseGroups ngroups) body
        (entries, _) = BG.runGet (parseEntries nentries) body' in
    KDBUnlocked <$>  groups <*> entries

parseGroups :: Int -> BG.Get [KGroup]
parseGroups ngroups = parseGroups' ngroups []

getLineData :: BG.Get (Word16, Word32, BS.ByteString)
getLineData = do
    ktype <- BG.getWord16le
    size <- BG.getWord32le
    kint <- if size > 4 then BG.lookAhead BG.getWord32le else return 0
    kdata <- BG.getByteString $ fromIntegral size
    return (ktype, kint, kdata)

parseGroups' :: Int -> [KGroupLine] -> BG.Get [KGroup]
parseGroups' 0 _ = return []
parseGroups' ngroups group = do
    (ktype, kint, kdata) <- getLineData
    case ktype of
        1 -> parseGroups' ngroups $ KGID (fromIntegral kint) : group
        2 -> parseGroups' ngroups $ KGTitle (C8.unpack kdata) : group
        0xffff -> (group:) <$> parseGroups (ngroups - 1)
        _ -> parseGroups' ngroups group  -- skip

parseEntries :: Int -> BG.Get [KEntry]
parseEntries ngroups = parseEntries' ngroups []

parseEntries' :: Int -> [KEntryLine] -> BG.Get [KEntry]
parseEntries' 0 _ = return []
parseEntries' nentries entry =  do
    (ktype, kint, kdata) <- getLineData
    case ktype of
        2 -> parseEntries' nentries $ KEGroupId (fromIntegral kint) : entry
        4 -> parseEntries' nentries $ KETitle (C8.unpack kdata) : entry
        5 -> parseEntries' nentries $ KEUrl (C8.unpack kdata) : entry
        6 -> parseEntries' nentries $ KEUsername (C8.unpack kdata) : entry
        7 -> parseEntries' nentries $ KEPassword (C8.unpack kdata) : entry
        8 -> parseEntries' nentries $ KEComment (C8.unpack kdata) : entry
        0xffff -> (entry:) <$> parseEntries (nentries - 1)
        _ -> parseEntries' nentries entry -- skip

-- filtering
entryContains :: KEntry -> String -> Bool
_ `entryContains` "" = True
entry `entryContains` s =  s' `isInfixOf` entry'
    where entry' = lowercase $ show entry -- hack hack
          s' = lowercase s
          lowercase = map toLower

safeHead :: [a] -> Maybe a
safeHead [] = Nothing
safeHead (x:_) = Just x

showLine :: (String, Maybe String) -> String
showLine (_, Nothing) = ""
showLine (label, Just content) = pad 20 label ++ content ++ "\n"

pad :: Int -> String -> String
pad n label = take n $ label ++ ":" ++ replicate n ' '

displayEntry :: [KGroup] -> KEntry -> String
displayEntry kgroups entry =
    concatMap showLine entries ++ replicate 50 '-' ++ "\n"
    where username = safeHead [x | KEUsername x <- entry]
          password = safeHead [x | KEPassword x <- entry]
          title = safeHead [x | KETitle x <- entry]
          url = safeHead [x | KEUrl x <- entry]
          comment = safeHead [x | KEComment x <- entry]
          kgid = safeHead [x | KEGroupId x <- entry]
          entries = [("Title", title),
                     ("Group", groupTitle kgroups kgid),
                     ("URL", url),
                     ("Username", username),
                     ("Password", password),
                     ("Comment", comment)]

groupTitle :: [[KGroupLine]] -> Maybe Int -> Maybe String
groupTitle _      Nothing    = Nothing
groupTitle groups (Just gid) = title
    where groupId group = head [x | KGID x <- group]
          groupAssoc = zip (map groupId groups) groups
          kgroup = case lookup gid groupAssoc of Just x -> x
          title = safeHead [x | KGTitle x <- kgroup]

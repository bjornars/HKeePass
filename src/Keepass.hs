module Keepass where

import qualified Data.ByteString.Lazy as L

type KEntry = (String, String)
data KMeta = KMeta deriving (Show)
data KDB = KDB KMeta [KEntry] deriving (Show)

loadKdb :: L.ByteString -> KDB
loadKdb = undefined

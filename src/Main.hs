module Main where

import qualified Data.ByteString.Lazy as L
import Keepass

file :: FilePath
file = "test.kdb"

main :: IO ()
main = do
    contents <- L.readFile file
    let db = loadKdb contents
    print db
    return ()

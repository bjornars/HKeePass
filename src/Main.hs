module Main where

import qualified Data.ByteString as BS
import Keepass

file :: FilePath
file = "test.kdb"

main :: IO ()
main = do
    contents <- BS.readFile file
    let db = loadKdb contents
    case db of
        (Left msg) -> putStrLn ("Error: " ++ msg)
        (Right msg) -> print msg

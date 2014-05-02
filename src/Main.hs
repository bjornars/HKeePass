module Main where

import qualified Data.ByteString as BS
import Keepass

import Control.Exception
import System.IO

file :: FilePath
file = "test.kdb"

main :: IO ()
main = do
    contents <- BS.readFile file
    let db = loadKdb contents
    case db of
        (Left msg) -> putStrLn ("Error: " ++ msg)
        (Right kdb) ->
            case kdb of
                (KDBLocked len _ _) -> do
                 putStrLn $ "read " ++ show len ++ " bytes"
                 unlockAndSearch kdb

unlockAndSearch :: KDBLocked -> IO ()
unlockAndSearch kdb = do
    putStr "password: "
    hFlush stdout
    pw <- noEcho getLine

    case decode kdb pw of
        (Left msg) -> putStrLn ("Error: " ++ msg) >> unlockAndSearch kdb
        (Right kdb') -> putStrLn "\ndecoding successful" >> search kdb'

search :: KDBUnlocked -> IO ()
search kdb = return ()

noEcho :: IO a -> IO a
noEcho = bracket_ (hSetEcho stdin False) (hSetEcho stdin True)

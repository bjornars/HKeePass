module Main where

import qualified Data.ByteString as BS
import Keepass

import Control.Applicative (liftA2)
import Control.Monad
import Control.Exception
import System.Environment
import System.IO

main :: IO ()
main = do
    args <- getArgs
    when (length args /= 1) $
        fail "usage: hkeepass <filename>"

    contents <- BS.readFile $ head args
    let db = loadKdb contents
    case db of
        (Left msg) -> putStrLn ("loadKdb error: " ++ msg)
        (Right kdb) -> do
             putStrLn $ "read " ++ show (kdbLength kdb) ++ " bytes"
             unlockAndSearch kdb

unlockAndSearch :: KDBLocked -> IO ()
unlockAndSearch kdb = do
    pw <- promptWith noEcho "password: "

    case decode kdb pw of
        (Left msg) -> putStrLn ("decode error: " ++ msg)
                      >> unlockAndSearch kdb
        (Right kdb') -> putStrLn "\ndecoding successful"
                      >> search kdb'

search :: KDBUnlocked -> IO ()
search kdb = do
    searchTerm <- prompt "search> "
    showSearch searchTerm kdb
    done  <- prompt "done? "
    case done of
        ('q':_) -> return ()
        _       -> replicateM_ 50 (putStrLn "") >> search kdb

showSearch :: String -> KDBUnlocked -> IO ()
showSearch searchTerm (KDBUnlocked groups entries) = do
    let matches = filter (liftA2 (&&)
                    (not.isMetaEntry)
                    (`entryContains` searchTerm))
                  entries
    forM_ matches (putStr . displayEntry groups)

noEcho :: IO a -> IO a
noEcho = bracket_ (hSetEcho stdin False) (hSetEcho stdin True)

promptWith :: (IO String -> IO String) -> String -> IO String
promptWith f str = putStr str >> hFlush stdout >> f getLine

prompt :: String -> IO String
prompt = promptWith id

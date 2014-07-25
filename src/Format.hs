module Format (
    displayEntry
  , isMetaEntry
  , entryContains
) where

import Keepass

import Data.Char
import Data.Maybe (listToMaybe, mapMaybe)
import Data.List

showEntry :: [KGroup] -> KEntryLine -> String
showEntry kgroups line = case line of
    (KETitle s) -> showLine "Title" s
    (KEUrl s) -> showLine "URL" s
    (KEUsername s) -> showLine "Username" s
    (KEPassword s) -> showLine "Password" s
    (KEComment s) -> showLine "Comment" s
    (KEGroupId g) -> showLine "Group" $ groupNameFromId g
    where
        showLine label content = pad 20 label ++ content ++ "\n"
        pad n label = take n $ label ++ ":" ++ replicate n ' '
        titleForGroupId gid = map snd
            $ filter ((==gid).fst)
            $ mapMaybe groupTuple kgroups

        groupNameFromId gid = last $ "N/A" : titleForGroupId gid



groupTuple :: [KGroupLine] -> Maybe (Int, String)
groupTuple kgroup = do
    gid <- listToMaybe [x | KGID x <- kgroup]
    title <- listToMaybe [x | KGTitle x <- kgroup]
    return (gid, title)


entryContains :: KEntry -> String -> Bool
_ `entryContains` "" = True
entry `entryContains` s =  s' `isInfixOf` entry'
    where entry' = lowercase $ show entry -- hack hack
          s' = lowercase s
          lowercase = map toLower

isMetaEntry :: KEntry -> Bool
isMetaEntry entry = or [True | KETitle "Meta-Info\000" <- entry]

displayEntry :: [KGroup] -> KEntry -> String
displayEntry kgroups entry =
        concatMap (showEntry kgroups) (sort entry) ++ line
    where
        line = replicate 50 '-' ++ "\n"

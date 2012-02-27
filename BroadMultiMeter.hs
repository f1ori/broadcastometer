--- |
--- | A Broad- & Multicast Meter
--- |
--- Copyright : (c) Florian Richter 2012
--- License : MIT
---

import Network.Pcap
import qualified Data.ByteString as B
import Numeric
import Text.Show
import System.Posix.Signals
import System.Exit
import qualified Data.Map as Map
import Data.Time.Clock
import Control.Concurrent.MVar
import Control.Monad
import Data.List
import Data.Ord


-- interval in milliseconds
interval = 3

data Stats = Stats {
      statsSrcMacs :: Map.Map B.ByteString Integer
    , statsDestMacs :: Map.Map B.ByteString Integer
    , statsLastUpdate :: DiffTime 
} deriving( Show )

incSrcMac :: B.ByteString -> Stats -> Stats
incSrcMac mac (Stats src dest up) = Stats (Map.insertWith' (+) mac 1 src) dest up

incDestMac :: B.ByteString -> Stats -> Stats
incDestMac mac (Stats src dest up) = Stats src (Map.insertWith' (+) mac 1 dest) up

showMac :: B.ByteString -> String
showMac mac = foldr1 (\x y->x++":"++y) (map (($"").showHex) (B.unpack mac))

getTopThree list = take 3 $ sortBy (comparing (negate.snd)) list

showStats :: Stats -> String
showStats stats = "src-macs:\n" ++ (showTopMacs topSrcMacs) ++ "dest-macs:\n" ++ (showTopMacs topDestMacs)
    where
        showTopMacs macs = concat $ map (\(mac,count) -> (showMac mac) ++": "++(show count)++"\n") macs
        topSrcMacs = getTopThree $ Map.toList $ statsSrcMacs stats
        topDestMacs = getTopThree $ Map.toList $ statsDestMacs stats

process :: MVar Stats -> PktHdr -> B.ByteString -> IO ()
process stats header buffer = do
    let srcmac = (B.take 6 (B.drop 6 buffer))
    let destmac = (B.take 6 buffer)
    let timestamp = hdrDiffTime header
    modifyMVar_ stats (\stat -> return $ incDestMac destmac $ incSrcMac srcmac stat)
    -- write stats in intervals
    lastupdate <- liftM statsLastUpdate $ readMVar stats
    if lastupdate + interval < timestamp
        then do
	    old_stats <- swapMVar stats (Stats Map.empty Map.empty timestamp)
	    putStrLn $ showStats old_stats
	else return ()

loopOverPackets handle stats = do
    dispatchBS handle (-1) (process stats)
    --putStrLn "loooop"
    loopOverPackets handle stats

main = do
    stats <- newMVar $ Stats {
        statsSrcMacs = Map.empty,
        statsDestMacs = Map.empty,
        statsLastUpdate = 0
    }
    installHandler keyboardTermination (Catch exitSuccess) Nothing
    handle <- openLive "eth0" 12 True 1000
    setFilter handle "ether multicast or ether broadcast" True 0
    loopOverPackets handle stats
    return 0

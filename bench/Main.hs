module Main where

import Crypto.PubKey.ECC.ElGamal (encrypt, decrypt)
import Crypto.PubKey.ECC.Types (Curve, PrivateNumber, PublicPoint)
import Crypto.PubKey.ECC.Types (getCurveByName)
import Data.Maybe (fromJust)
import Fixtures (Key, keys, clearText)
import Gauge (Benchmark, defaultMain, env, bgroup, bench, nf, nfIO)

main :: IO ()
main = defaultMain $ map (\k -> benchCurve k clearText) keys

benchCurve :: Key -> Integer -> Benchmark
benchCurve (curveName, privateKey, publicKey) message
  = bgroup (show curveName)
           [ (benchEncrypt curve publicKey message)
           , (benchDecrypt curve privateKey publicKey message)
           ]
  where curve = getCurveByName curveName

benchEncrypt :: Curve -> PublicPoint -> Integer -> Benchmark
benchEncrypt curve publicKey message
  = bench "encrypt" $ nfIO $ encrypt curve publicKey message

benchDecrypt :: Curve -> PrivateNumber -> PublicPoint -> Integer -> Benchmark
benchDecrypt curve privateKey publicKey message
  = env (encrypt curve publicKey message)
  $ \c -> bench "decrypt" $ nf (decrypt curve privateKey) (fromJust c)

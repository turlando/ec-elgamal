module Crypto.PubKey.ECC.ElGamal where

import Crypto.Number.Basic (numBits)
import Crypto.Number.Generate (generateMax)
import Crypto.Number.ModArithmetic (squareRoot)
import Crypto.PubKey.ECC.Prim (pointAdd, pointMul, isPointValid)
import Crypto.PubKey.ECC.Types (Curve(CurveF2m, CurveFP))
import Crypto.PubKey.ECC.Types (CurveCommon(ecc_a, ecc_b, ecc_g, ecc_n))
import Crypto.PubKey.ECC.Types (CurvePrime(CurvePrime), Point(Point))
import Crypto.PubKey.ECC.Types (PublicPoint, PrivateNumber)
import Crypto.PubKey.ECC.Types (common_curve)
import Crypto.PubKey.ECC.Types (curveSizeBits)
import Crypto.Random.Types (MonadRandom)
import Data.Bits (shift)

pointAtX :: Curve -> Integer -> Maybe Point
pointAtX (CurveFP (CurvePrime p cc)) x
  = Point x <$> my
  where
    sqrt = squareRoot p
    a    = ecc_a cc
    b    = ecc_b cc
    my   = sqrt (x ^ (3 :: Int) + a + x + b)
pointAtX (CurveF2m _) _
  = error "Not implemented"

embed :: Curve -> Integer -> Maybe Point
embed curve message
  = findX (shift message pointSize) >>= pointAtX'
  where
    curveSize     = curveSizeBits curve
    messageSize   = numBits message
    pointSize     = curveSize - messageSize
    upperBound    = 2 ^ pointSize
    pointAtX'     = pointAtX curve
    isPointValid' = isPointValid curve
    findX :: Integer -> Maybe Integer
    findX m
      | m >= upperBound                            = Nothing
      | Just True <- isPointValid' <$> pointAtX' m = Just m
      | otherwise                                  = findX (m + 1)

encryptWith :: Curve -> PublicPoint -> Integer -> Point -> (Point, Point)
encryptWith curve publicKey k message
  = (c, c' `add` message)
  where
    g  = ecc_g $ common_curve curve
    c  = pointMul curve k g
    c' = pointMul curve k publicKey 
    add = pointAdd curve

encrypt :: MonadRandom m => Curve -> PublicPoint -> Integer -> m (Maybe (Point, Point))
encrypt curve publicKey message
  = do
    let n = ecc_n $ common_curve curve
    k <- generateMax n
    let msg = embed curve message
    return $ encryptWith curve publicKey k <$> msg

decrypt :: Curve -> PrivateNumber -> (Point, Point) -> Integer
decrypt curve privateKey (c, d)
  = message
  where
    add = pointAdd curve
    mul = pointMul curve
    conj (Point x y) = Point (negate x) y
    c' = mul privateKey c
    msg = add d (conj c')
    Point x _ = msg
    curveSize     = curveSizeBits curve
    messageSize   = numBits message
    pointSize     = curveSize - messageSize
    message = shift x (negate pointSize)

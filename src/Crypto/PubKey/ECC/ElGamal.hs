module Crypto.PubKey.ECC.ElGamal where

import Prelude hiding (sqrt)
import Crypto.Number.Basic (numBits)
import Crypto.Number.ModArithmetic (squareRoot)
import Crypto.PubKey.ECC.DH (generatePrivate)
import Crypto.PubKey.ECC.Prim (pointAdd, pointNegate, pointMul, isPointValid)
import Crypto.PubKey.ECC.Types (Curve(CurveF2m, CurveFP))
import Crypto.PubKey.ECC.Types (CurveCommon(ecc_a, ecc_b, ecc_g))
import Crypto.PubKey.ECC.Types (CurvePrime(CurvePrime))
import Crypto.PubKey.ECC.Types (Point(Point, PointO))
import Crypto.PubKey.ECC.Types (PublicPoint, PrivateNumber)
import Crypto.PubKey.ECC.Types (common_curve)
import Crypto.PubKey.ECC.Types (curveSizeBits)
import Crypto.Random.Types (MonadRandom)
import Data.Bits (shift)

blockSize :: Int
blockSize = 4 * 8 -- 4 bytes in bits

pointAtX :: Curve -> Integer -> Maybe Point
pointAtX (CurveFP (CurvePrime p cc)) x
  -- y² = x³ + ax + b (mod p)
  = Point x <$> my
  where
    sqrt = squareRoot p
    a    = ecc_a cc
    b    = ecc_b cc
    my   = sqrt (x ^ (3 :: Integer) + a * x + b)
pointAtX (CurveF2m _) _x
  = error "Not implemented"

embed :: Curve -> Integer -> Maybe Point
embed curve message
  = if numBits message > blockSize
    then error "message size exceeds block size"
    else embed' curve message

embed' :: Curve -> Integer -> Maybe Point
embed' curve message
  = findX 0 startingPoint >>= pointAtX'
  where
    curveSize     = curveSizeBits curve
    pointSize     = curveSize - blockSize -- make sure it's not negative
    upperBound    = (toInteger pointSize) ^ (2 :: Integer)
    pointAtX'     = pointAtX curve
    isPointValid' = isPointValid curve
    startingPoint = shift message pointSize
    findX :: Integer -> Integer -> Maybe Integer
    findX i m
      | i >= upperBound                            = Nothing
      | Just True <- isPointValid' <$> pointAtX' m = Just m
      | otherwise                                  = findX (i + 1) (m + 1)

unembed :: Curve -> Point -> Integer
unembed curve (Point x _y)
  = shift x (negate pointSize)
  where
    curveSize = curveSizeBits curve
    pointSize = curveSize - blockSize
unembed _curve (PointO)
  = 0

encryptWith :: Curve -> PublicPoint -> Integer -> Point -> (Point, Point)
encryptWith curve publicKey rand message
  = (c, c' `add` message)
  where
    add = pointAdd curve
    mul = pointMul curve
    g  = ecc_g $ common_curve curve
    c  = mul rand g
    c' = mul rand publicKey

encrypt :: MonadRandom m => Curve -> PublicPoint -> Integer -> m (Maybe (Point, Point))
encrypt curve publicKey message
  =  do
      rand <- generatePrivate curve
      return $ encryptWith curve publicKey rand <$> embed curve message

decrypt :: Curve -> PrivateNumber -> (Point, Point) -> Integer
decrypt curve privateKey (c, d)
  = unembed curve msg
  where
    add = pointAdd curve
    mul = pointMul curve
    neg = pointNegate curve
    c' = mul privateKey c
    msg = add d (neg c')

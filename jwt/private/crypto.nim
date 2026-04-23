import bearssl

proc bearHMAC*(digestVtable: ptr HashClass; key, d: string): seq[byte] =
  var hKey: HmacKeyContext
  var hCtx: HmacContext
  hmacKeyInit(addr hKey, digestVtable, key.cstring, key.len)
  hmacInit(addr hCtx, addr hKey, 0)
  hmacUpdate(addr hCtx, d.cstring, d.len)
  let sz = hmacSize(addr hCtx)
  result = newSeqUninitialized[byte](sz)
  discard hmacOut(addr hCtx, addr result[0])

proc bearSignRSPem*(data, key: string, alg: ptr HashClass, hashOid: cstring, hashLen: int): seq[byte] =
  raise newException(Exception, "RSA signing is not supported in this nim-jwt workspace patch")

proc bearVerifyRSPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashOid: cstring, hashLen: int): bool =
  raise newException(Exception, "RSA verification is not supported in this nim-jwt workspace patch")

# const ecPublicKey = """-----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
# q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
# -----END PUBLIC KEY-----"""

# var EC_P256_PUB_POINT = @[
#   0x04.uint8, 0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D,
#   0x31, 0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D,
#   0x68, 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA,
#   0x6C, 0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F,
#   0xB6, 0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC,
#   0x99, 0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC,
#   0x64, 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F,
#   0x51, 0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22,
#   0x99
# ]

# var EC_P256_PRIV_X = @[
#   0xC9.uint8, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16,
#   0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
#   0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
#   0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
# ]


proc bearSignECPem*(data, key: string, alg: ptr HashClass, impl: ptr EcImpl): seq[byte] =
  raise newException(Exception, "EC signing is not supported in this nim-jwt workspace patch")

proc bearVerifyECPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, impl: ptr EcImpl, hashLen: int): bool =
  raise newException(Exception, "EC verification is not supported in this nim-jwt workspace patch")

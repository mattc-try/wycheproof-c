def _lazy_import_xdh_parsers():
    from .xdh_parsers import XdhParser, XdhPemParser, XdhJwkParser, XdhAsnParser
    return {
        "XdhParser": XdhParser,
        "XdhPemParser": XdhPemParser,
        "XdhJwkParser": XdhJwkParser,
        "XdhAsnParser": XdhAsnParser,
    }

def _lazy_import_ecdh_parsers():
    from .ecdh_parsers import EcdhParser, EcdhEcPointParser, EcdhWebCryptoParser
    return {
        "EcdhParser": EcdhParser,
        "EcdhEcPointParser": EcdhEcPointParser,
        "EcdhWebCryptoParser": EcdhWebCryptoParser,
    }

def _lazy_import_ecdsa_parsers():
    from .ecdsa_parsers import EcdsaParser, EcdsaP1363Parser
    return {
        "EcdsaParser": EcdsaParser,
        "EcdsaP1363Parser": EcdsaP1363Parser,
    }

def _lazy_import_dsa_parsers():
    from .dsa_parsers import DsaParser, DsaP1363Parser
    return {
        "DsaParser": DsaParser,
        "DsaP1363Parser": DsaP1363Parser,
    }

def _lazy_import_rsa_parsers():
    from .rsa_parsers import (
        RsaOaepDecryptParser,
        RsaPkcs1DecryptParser,
        RsassaPkcs1GenerateParser,
        RsassaPkcs1VerifyParser,
        RsassaPssVerifyParser,
    )
    return {
        "RsaOaepDecryptParser": RsaOaepDecryptParser,
        "RsaPkcs1DecryptParser": RsaPkcs1DecryptParser,
        "RsassaPkcs1GenerateParser": RsassaPkcs1GenerateParser,
        "RsassaPkcs1VerifyParser": RsassaPkcs1VerifyParser,
        "RsassaPssVerifyParser": RsassaPssVerifyParser,
    }

# Consolidate everything into a single namespace
_parsers = {}
_parsers.update(_lazy_import_xdh_parsers())
_parsers.update(_lazy_import_ecdh_parsers())
_parsers.update(_lazy_import_ecdsa_parsers())
_parsers.update(_lazy_import_dsa_parsers())
_parsers.update(_lazy_import_rsa_parsers())

# Make available as package-level imports
globals().update(_parsers)

import os
from parse import (
    XdhParser, XdhPemParser, XdhJwkParser, XdhAsnParser,
    EcdhParser, EcdhEcPointParser, EcdhWebCryptoParser,
    EcdsaParser, EcdsaP1363Parser,
    DsaParser, DsaP1363Parser,
    RsaOaepDecryptParser, RsaPkcs1DecryptParser,
    RsassaPkcs1GenerateParser, RsassaPkcs1VerifyParser, RsassaPssVerifyParser,
)

def get_target_files(directory_path, prefixes, suffix, exclusion=None):
    """
    Fetch target files matching specific prefixes and suffix in the directory.
    Optionally exclude files containing specific substrings.
    
    :param directory_path: Directory where JSON test vectors are stored
    :param prefixes: Tuple of prefixes to filter files
    :param suffix: Suffix to filter files
    :param exclusion: Tuple of substrings to exclude files containing them
    :return: List of matching file names.
    """
    if not os.path.exists(directory_path):
        print(f"Directory '{directory_path}' does not exist.")
        return []

    # Ensure prefixes is a tuple of strings
    if isinstance(prefixes, str):
        prefixes = (prefixes,)

    # Ensure exclusion is a tuple of strings
    if exclusion and isinstance(exclusion, str):
        exclusion = (exclusion,)

    # Get all files in directory
    all_files = os.listdir(directory_path)

    # Apply prefix and suffix filtering
    matching_files = [
        f for f in all_files
        if f.endswith(suffix) and f.startswith(prefixes)
    ]

    # Debugging Step: Print matching files before exclusion
    print(f"Matching files before exclusion: {matching_files}")

    # Apply exclusion filtering if needed
    if exclusion:
        excluded_files = [f for f in matching_files if any(excl in f for excl in exclusion)]
        print(f"Excluded files: {excluded_files}")
        matching_files = [f for f in matching_files if not any(excl in f for excl in exclusion)]

    # Debugging Step: Print final selected files
    print(f"Final selected files: {matching_files}")

    return matching_files






def get_parsers():
    """Returns a centralized list of parsers with their metadata."""
    return [
        ("XDH", XdhParser, ("x25519", "x448"), "_test.json", './parsed_vectors/tv_XdhComp.h', {"exclude": ("jwk", "pem", "asn")}),
        ("XDH PEM", XdhPemParser, ("x25519_pem", "x448_pem"), "_test.json", './parsed_vectors/tv_XdhPemComp.h', {}),
        ("XDH JWK", XdhJwkParser, ("x25519_jwk", "x448_jwk"), "_test.json", './parsed_vectors/tv_XdhJwkComp.h', {}),
        ("XDH ASN", XdhAsnParser, ("x25519_asn", "x448_asn"), "_test.json", './parsed_vectors/tv_XdhAsnComp.h', {}),
        ("ECDH", EcdhParser, ("ecdh"), "_test.json", './parsed_vectors/tv_EcdhTest.h', {"exclude": ("webcrypto", "ecpoint")}),
        ("ECDH ECPoint", EcdhEcPointParser, ("ecdh"), "_ecpoint_test.json", './parsed_vectors/tv_EcdhEcpoint.h', {}),
        ("ECDH WebCrypto", EcdhWebCryptoParser, ("ecdh"), "_webcrypto_test.json", './parsed_vectors/tv_EcdhWebcrypto.h', {}),
        ("ECDSA", EcdsaParser, ("ecdsa_"), "test.json", './parsed_vectors/tv_Ecdsa.h', {"exclude": ("p1363")}),
        ("ECDSA P1363", EcdsaP1363Parser, ("ecdsa"), "p1363_test.json", './parsed_vectors/tv_EcdsaP1363.h', {}),
        ("DSA", DsaParser, ("dsa_"), "test.json", './parsed_vectors/tv_DsaTest.h', {"exclude": ("p1363")}),
        ("DSA P1363", DsaP1363Parser, ("dsa"), "p1363_test.json", './parsed_vectors/tv_DsaP1363Test.h', {}),
        ("RSA OAEP Decrypt", RsaOaepDecryptParser, ("rsa_oaep_"), "_test.json", './parsed_vectors/tv_RsaesOaepDecrypt.h', {}),
        ("RSA PKCS1 Decrypt", RsaPkcs1DecryptParser, ("rsa_pkcs1_"), "_test.json", './parsed_vectors/tv_RsaPkcs1Decrypt.h', {}),
        ("RSA PKCS1 Generate", RsassaPkcs1GenerateParser, ("rsa_sig_gen"), "_test.json", './parsed_vectors/tv_RsassaPkcs1Generate.h', {}),
        ("RSA PKCS1 Verify", RsassaPkcs1VerifyParser, ("rsa_signature"), "_test.json", './parsed_vectors/tv_RsassaPkcs1Verify.h', {}),
        ("RSA PSS Verify", RsassaPssVerifyParser, ("rsa_pss_"), "_test.json", './parsed_vectors/tv_RsassaPssVerify.h', {}),
    ]


def main():
    print("Welcome to the test vector parser.")
    print("Please choose an option:")
    print("1. Parse specific algorithm")
    print("2. Parse all algorithms")
    choice = input("Enter your choice (1/2): ")

    if choice == "1":
        parse_specific_algorithm()
    elif choice == "2":
        parse_all_algorithms()
    else:
        print("Invalid choice. Exiting.")


def parse_specific_algorithm():
    parsers = get_parsers()
    print("Choose an algorithm to parse:")
    for idx, (name, _, _, _, _, _) in enumerate(parsers, start=1):
        print(f"{idx}. {name}")
    selection = input("Enter the number of the algorithm to parse: ")

    try:
        idx = int(selection) - 1
        name, parser_class, prefix, suffix, output, extra = parsers[idx]
    except (ValueError, IndexError):
        print("Invalid selection. Exiting.")
        return

    directory_path = 'pk_testvectors/'
    exclusion = extra.get("exclude") if extra else None
    target_files = get_target_files(directory_path, prefix, suffix, exclusion)

    print(f"Processing files for {name}: {target_files}")

    if not target_files:
        print(f"No matching files found for {name}. Exiting.")
        return

    parser = parser_class(
        directory_path=directory_path,
        output_c_header=output,
        target_files=target_files,
    )
    print(f"Parsing {name}...")
    parser.parse()
    print(f"Finished parsing {name}. Output written to {output}.")


def parse_all_algorithms():
    parsers = get_parsers()
    directory_path = 'pk_testvectors/'

    print("Parsing all algorithms...")
    for name, parser_class, prefix, suffix, output, extra in parsers:
        exclusion = extra.get("exclude") if extra else None
        target_files = get_target_files(directory_path, prefix, suffix, exclusion)

        print(f"Processing files for {name}: {target_files}")

        if not target_files:
            print(f"No matching files found for {name}. Skipping.")
            continue

        parser = parser_class(
            directory_path=directory_path,
            output_c_header=output,
            target_files=target_files,
        )
        print(f"Parsing {name}...")
        parser.parse()
        print(f"Finished parsing {name}. Output written to {output}.")

    print("Finished parsing all algorithms.")


if __name__ == "__main__":
    main()

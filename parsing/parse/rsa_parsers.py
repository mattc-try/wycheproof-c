
import binascii
from .base_parser import BaseParser

class RsaOaepDecryptParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from RSAES-OAEP Decrypt test vectors */\n"
            "#ifndef TEST_VECTORS_RSA_OAEP_DECRYPT_H\n#define TEST_VECTORS_RSA_OAEP_DECRYPT_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* comment;\n"
            "    const char* result;\n"
            "    const char* msg_hex;\n"
            "    size_t msg_len;\n"
            "    const char* ct_hex;\n"
            "    size_t ct_len;\n"
            "    const char* label_hex;\n"
            "    size_t label_len;\n"
            "    const char* sha;\n"
            "    const char* mgf;\n"
            "    const char* mgf_sha;\n"
            "    const char* private_key_pem;\n"
            "    int key_size;\n"
            "    const char* flags[5];\n"
            "    size_t flags_len;\n"
            "} RsaOaepDecryptTestCase;\n\n"
            "static const RsaOaepDecryptTestCase rsa_oaep_decrypt_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        content = ""
        private_key_pem = group.get("privateKeyPem", "").replace("\n", "\\n")
        sha = group.get("sha", "").replace("\n", "\\n")
        mgf = group.get("mgf", "").replace("\n", "\\n")
        mgf_sha = group.get("mgfSha", "").replace("\n", "\\n")
        key_size = group.get("keySize", 0)

        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            comment = test.get("comment", "").replace("\n", "\\n")
            result = test.get("result", "")
            msg_hex = test.get("msg", "")
            ct_hex = test.get("ct", "")
            label_hex = test.get("label", "")
            flags = test.get("flags", [])

            msg_len = len(msg_hex)//2 if msg_hex else 0
            ct_len = len(ct_hex)//2 if ct_hex else 0
            label_len = len(label_hex)//2 if label_hex else 0

            content += f"    {{ {tc_id}, \"{comment}\", \"{result}\", \"{msg_hex}\", {msg_len}, \"{ct_hex}\", {ct_len}, \"{label_hex}\", {label_len}, \"{sha}\", \"{mgf}\", \"{mgf_sha}\", \"{private_key_pem}\", {key_size}, {{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
        return content


class RsaPkcs1DecryptParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from RSAES-PKCS1 Decrypt test vectors */\n"
            "#ifndef TEST_VECTORS_RSA_PKCS1_DECRYPT_H\n#define TEST_VECTORS_RSA_PKCS1_DECRYPT_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* comment;\n"
            "    const char* result;\n"
            "    const char* msg_hex;\n"
            "    size_t msg_len;\n"
            "    const char* ct_hex;\n"
            "    size_t ct_len;\n"
            "    const char* private_key_pem;\n"
            "    int key_size;\n"
            "    const char* flags[5];\n"
            "    size_t flags_len;\n"
            "} RsaPkcs1DecryptTestCase;\n\n"
            "static const RsaPkcs1DecryptTestCase rsa_pkcs1_decrypt_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        content = ""
        private_key_pem = group.get("privateKeyPem", "").replace("\n", "\\n")
        key_size = group.get("keySize", 0)

        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            comment = test.get("comment", "").replace("\n", "\\n")
            result = test.get("result", "")
            msg_hex = test.get("msg", "")
            ct_hex = test.get("ct", "")
            flags = test.get("flags", [])

            msg_len = len(msg_hex)//2 if msg_hex else 0
            ct_len = len(ct_hex)//2 if ct_hex else 0

            content += f"    {{ {tc_id}, \"{comment}\", \"{result}\", \"{msg_hex}\", {msg_len}, \"{ct_hex}\", {ct_len}, \"{private_key_pem}\", {key_size}, {{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
        return content


class RsassaPkcs1GenerateParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from RSASSA-PKCS1 Signature Generation test vectors */\n"
            "#ifndef TEST_VECTORS_RSASSA_PKCS1_GEN_H\n#define TEST_VECTORS_RSASSA_PKCS1_GEN_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* comment;\n"
            "    const char* msg_hex;\n"
            "    size_t msg_len;\n"
            "    const char* sig_hex;\n"
            "    size_t sig_len;\n"
            "    const char* sha;\n"
            "    const char* private_key_pem;\n"
            "    int key_size;\n"
            "} RsassaPkcs1GenerateTestCase;\n\n"
            "static const RsassaPkcs1GenerateTestCase rsassa_pkcs1_generate_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        content = ""
        private_key_pem = group.get("privateKeyPem", "").replace("\n", "\\n")
        sha = group.get("sha", "").replace("\n", "\\n")
        key_size = group.get("keySize", 0)

        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            comment = test.get("comment", "").replace("\n", "\\n")
            msg_hex = test.get("msg", "")
            sig_hex = test.get("sig", "")

            msg_len = len(msg_hex)//2 if msg_hex else 0
            sig_len = len(sig_hex)//2 if sig_hex else 0

            content += f"    {{ {tc_id}, \"{comment}\", \"{msg_hex}\", {msg_len}, \"{sig_hex}\", {sig_len}, \"{sha}\", \"{private_key_pem}\", {key_size} }},\n"
        return content


class RsassaPkcs1VerifyParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from RSASSA-PKCS1 Signature Verification test vectors */\n"
            "#ifndef TEST_VECTORS_RSASSA_PKCS1_VERIFY_H\n#define TEST_VECTORS_RSASSA_PKCS1_VERIFY_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* comment;\n"
            "    const char* result;\n"
            "    const char* msg_hex;\n"
            "    size_t msg_len;\n"
            "    const char* sig_hex;\n"
            "    size_t sig_len;\n"
            "    const char* public_key_pem;\n"
            "    int key_size;\n"
            "    const char* flags[5];\n"
            "    size_t flags_len;\n"
            "} RsassaPkcs1VerifyTestCase;\n\n"
            "static const RsassaPkcs1VerifyTestCase rsassa_pkcs1_verify_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        content = ""
        public_key_pem = group.get("publicKeyPem", "").replace("\n", "\\n")
        key_size = group.get("keySize", 0)

        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            comment = test.get("comment", "").replace("\n", "\\n")
            result = test.get("result", "")
            msg_hex = test.get("msg", "")
            sig_hex = test.get("sig", "")
            flags = test.get("flags", [])

            msg_len = len(msg_hex)//2 if msg_hex else 0
            sig_len = len(sig_hex)//2 if sig_hex else 0

            content += f"    {{ {tc_id}, \"{comment}\", \"{result}\", \"{msg_hex}\", {msg_len}, \"{sig_hex}\", {sig_len}, \"{public_key_pem}\", {key_size}, {{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
        return content


class RsassaPssVerifyParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from RSASSA-PSS Signature Verification test vectors */\n"
            "#ifndef TEST_VECTORS_RSASSA_PSS_VERIFY_H\n#define TEST_VECTORS_RSASSA_PSS_VERIFY_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* comment;\n"
            "    const char* result;\n"
            "    const char* msg_hex;\n"
            "    size_t msg_len;\n"
            "    const char* sig_hex;\n"
            "    size_t sig_len;\n"
            "    const char* public_key_pem;\n"
            "    int key_size;\n"
            "    const char* flags[5];\n"
            "    size_t flags_len;\n"
            "} RsassaPssVerifyTestCase;\n\n"
            "static const RsassaPssVerifyTestCase rsassa_pss_verify_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        content = ""
        public_key_pem = group.get("publicKeyPem", "").replace("\n", "\\n")
        key_size = group.get("keySize", 0)

        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            comment = test.get("comment", "").replace("\n", "\\n")
            result = test.get("result", "")
            msg_hex = test.get("msg", "")
            sig_hex = test.get("sig", "")
            flags = test.get("flags", [])

            msg_len = len(msg_hex)//2 if msg_hex else 0
            sig_len = len(sig_hex)//2 if sig_hex else 0

            content += f"    {{ {tc_id}, \"{comment}\", \"{result}\", \"{msg_hex}\", {msg_len}, \"{sig_hex}\", {sig_len}, \"{public_key_pem}\", {key_size}, {{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
        return content

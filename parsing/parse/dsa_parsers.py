import binascii
from .base_parser import BaseParser

# Standard DSA Parser
class DsaParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from DSA test vectors */\n"
            "#ifndef TEST_VECTORS_DSA_H\n#define TEST_VECTORS_DSA_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* comment;\n"
            "    const char* result;\n"
            "    unsigned char msg[256];\n"  # Adjust size dynamically if needed
            "    size_t msg_len;\n"
            "    unsigned char sig[256];\n"  # Adjust size dynamically if needed
            "    size_t sig_len;\n"
            "    const char* sha;\n"
            "    const char* public_key_pem;\n"
            "    int key_size;\n"
            "    const char* flags[5];\n"  # Maximum flags; adjust if needed
            "    size_t flags_len;\n"
            "} DsaTestCase;\n\n"
            "static const DsaTestCase dsa_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        public_key_pem = group.get("publicKeyPem", "")
        sha = group.get("sha", "")
        key_size = group.get("publicKey", {}).get("keySize", 0)
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            comment = test.get("comment", "")
            msg_hex = test.get("msg", "")
            sig_hex = test.get("sig", "")
            result = test.get("result", "")
            flags = test.get("flags", [])
            msg_bytes = binascii.unhexlify(msg_hex) if msg_hex else b""
            sig_bytes = binascii.unhexlify(sig_hex) if sig_hex else b""
            content += (
                f"    {{ {tc_id}, \"{comment}\", \"{result}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in msg_bytes)} }}, {len(msg_bytes)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in sig_bytes)} }}, {len(sig_bytes)}, "
                f"\"{sha}\", \"{public_key_pem}\", {key_size}, "
                f"{{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
            )
        return content


# P1363 DSA Parser
class DsaP1363Parser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from DSA P1363 test vectors */\n"
            "#ifndef TEST_VECTORS_DSA_P1363_H\n#define TEST_VECTORS_DSA_P1363_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* comment;\n"
            "    const char* result;\n"
            "    unsigned char msg[256];\n"  # Adjust size dynamically if needed
            "    size_t msg_len;\n"
            "    unsigned char sig[256];\n"  # Adjust size dynamically if needed
            "    size_t sig_len;\n"
            "    const char* sha;\n"
            "    const char* public_key_pem;\n"
            "    int key_size;\n"
            "    const char* flags[5];\n"  # Maximum flags; adjust if needed
            "    size_t flags_len;\n"
            "} DsaP1363TestCase;\n\n"
            "static const DsaP1363TestCase dsa_p1363_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        public_key_pem = group.get("publicKeyPem", "")
        sha = group.get("sha", "")
        key_size = group.get("publicKey", {}).get("keySize", 0)
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            comment = test.get("comment", "")
            msg_hex = test.get("msg", "")
            sig_hex = test.get("sig", "")
            result = test.get("result", "")
            flags = test.get("flags", [])
            msg_bytes = binascii.unhexlify(msg_hex) if msg_hex else b""
            sig_bytes = binascii.unhexlify(sig_hex) if sig_hex else b""
            content += (
                f"    {{ {tc_id}, \"{comment}\", \"{result}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in msg_bytes)} }}, {len(msg_bytes)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in sig_bytes)} }}, {len(sig_bytes)}, "
                f"\"{sha}\", \"{public_key_pem}\", {key_size}, "
                f"{{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
            )
        return content

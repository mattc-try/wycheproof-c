
import binascii
from .base_parser import BaseParser

# Standard ECDSA Parser
class EcdsaParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from ECDSA test vectors */\n"
            "#ifndef TEST_VECTORS_ECDSA_H\n#define TEST_VECTORS_ECDSA_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    const char* sha;\n"
            "    const char* wx;\n"
            "    const char* wy;\n"
            "    unsigned char msg[256];\n"
            "    size_t msg_len;\n"
            "    unsigned char sig[256];\n"
            "    size_t sig_len;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "} EcdsaTestCase;\n\n"
            "static const EcdsaTestCase ecdsa_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("publicKey", {}).get("curve", "unknown_curve")
        sha = group.get("sha", "unknown_sha")
        wx = group.get("publicKey", {}).get("wx", "")
        wy = group.get("publicKey", {}).get("wy", "")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            msg_hex = test.get("msg", "")
            sig_hex = test.get("sig", "")
            result = test.get("result", "")
            comment = test.get("comment", "")
            
            # Escape double quotes in comment
            comment_escaped = comment.replace('"', '\\"')
            
            msg_bytes = binascii.unhexlify(msg_hex) if msg_hex else b""
            sig_bytes = binascii.unhexlify(sig_hex) if sig_hex else b""
            content += (
                f"    {{ {tc_id}, \"{curve}\", \"{sha}\", \"{wx}\", \"{wy}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in msg_bytes)} }}, {len(msg_bytes)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in sig_bytes)} }}, {len(sig_bytes)}, "
                f"\"{result}\", \"{comment_escaped}\" }},\n"
            )
        return content


# P1363 ECDSA Parser
class EcdsaP1363Parser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from ECDSA P1363 test vectors */\n"
            "#ifndef TEST_VECTORS_ECDSAP1363_H\n#define TEST_VECTORS_ECDSAP1363_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    const char* sha;\n"
            "    const char* wx;\n"
            "    const char* wy;\n"
            "    unsigned char msg[256];\n"
            "    size_t msg_len;\n"
            "    unsigned char sig[256];\n"
            "    size_t sig_len;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "} EcdsaP1363TestCase;\n\n"
            "static const EcdsaP1363TestCase ecdsa_p1363_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("publicKey", {}).get("curve", "unknown_curve")
        sha = group.get("sha", "unknown_sha")
        wx = group.get("publicKey", {}).get("wx", "")
        wy = group.get("publicKey", {}).get("wy", "")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            msg_hex = test.get("msg", "")
            sig_hex = test.get("sig", "")
            result = test.get("result", "")
            comment = test.get("comment", "")
            
            # Escape double quotes in comment
            comment_escaped = comment.replace('"', '\\"')
            
            msg_bytes = binascii.unhexlify(msg_hex) if msg_hex else b""
            sig_bytes = binascii.unhexlify(sig_hex) if sig_hex else b""
            content += (
                f"    {{ {tc_id}, \"{curve}\", \"{sha}\", \"{wx}\", \"{wy}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in msg_bytes)} }}, {len(msg_bytes)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in sig_bytes)} }}, {len(sig_bytes)}, "
                f"\"{result}\", \"{comment_escaped}\" }},\n"
            )
        return content

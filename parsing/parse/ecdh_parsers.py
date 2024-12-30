import binascii
from .base_parser import BaseParser

# Standard ECDH Parser
class EcdhParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from ECDH test vectors */\n"
            "#ifndef TEST_VECTORS_ECDH_H\n#define TEST_VECTORS_ECDH_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    const char* encoding;\n"
            "    const char* public_key;\n"
            "    const char* private_key;\n"
            "    const char* shared_secret;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "} EcdhTestCase;\n\n"
            "static const EcdhTestCase ecdh_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("curve", "unknown_curve")
        encoding = group.get("encoding", "unknown_encoding")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            public_key = test.get("public", "").replace("\n", "\\n")
            private_key = test.get("private", "").replace("\n", "\\n")
            shared_secret = test.get("shared", "")
            result = test.get("result", "")
            comment = test.get("comment", "")
            content += (
                f"    {{ {tc_id}, \"{curve}\", \"{encoding}\", \"{public_key}\", \"{private_key}\", "
                f"\"{shared_secret}\", \"{result}\", \"{comment}\" }},\n"
            )
        return content


# ECPoint ECDH Parser
class EcdhEcPointParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from ECPoint ECDH test vectors */\n"
            "#ifndef TEST_VECTORS_ECDHECPOINT_H\n#define TEST_VECTORS_ECDHECPOINT_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    const char* encoding;\n"
            "    const char* public_key;\n"
            "    const char* private_key;\n"
            "    const char* shared_secret;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "} EcdhEcPointTestCase;\n\n"
            "static const EcdhEcPointTestCase ecdhecpoint_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("curve", "unknown_curve")
        encoding = group.get("encoding", "unknown_encoding")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            public_key = test.get("public", "")
            private_key = test.get("private", "")
            shared_secret = test.get("shared", "")
            result = test.get("result", "")
            comment = test.get("comment", "")
            content += (
                f"    {{ {tc_id}, \"{curve}\", \"{encoding}\", \"{public_key}\", \"{private_key}\", "
                f"\"{shared_secret}\", \"{result}\", \"{comment}\" }},\n"
            )
        return content


# WebCrypto ECDH Parser
class EcdhWebCryptoParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from WebCrypto ECDH test vectors */\n"
            "#ifndef TEST_VECTORS_WEBCYPTO_H\n#define TEST_VECTORS_WEBCYPTO_H\n"
            "#include <stddef.h>\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    const char* encoding;\n"
            "    const char* public_x;\n"
            "    const char* public_y;\n"
            "    const char* private_d;\n"
            "    const char* shared_secret;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "} EcdhWebCryptoTestCase;\n\n"
            "static const EcdhWebCryptoTestCase ecdhwebcrypto_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("curve", "unknown_curve")
        encoding = group.get("encoding", "unknown_encoding")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            public_key = test.get("public", {})
            public_x = public_key.get("x", "")
            public_y = public_key.get("y", "")
            private_key = test.get("private", {})
            private_d = private_key.get("d", "")
            shared_secret = test.get("shared", "")
            result = test.get("result", "")
            comment = test.get("comment", "")
            content += (
                f"    {{ {tc_id}, \"{curve}\", \"{encoding}\", \"{public_x}\", \"{public_y}\", "
                f"\"{private_d}\", \"{shared_secret}\", \"{result}\", \"{comment}\" }},\n"
            )
        return content

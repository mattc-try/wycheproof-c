import os
import json
import binascii
from .base_parser import BaseParser


# Base XDH Parser class
class BaseXDHParser:
    def __init__(self, directory_path, output_c_header, target_files):
        self.directory_path = directory_path
        self.output_c_header = output_c_header
        self.target_files = target_files

    def escape_string(self, s):
        """Escapes special characters in strings for C headers."""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

    def read_json(self, file_path):
        """Reads and parses a JSON file."""
        with open(file_path, 'r') as file:
            return json.load(file)

    def write_header(self, header_content):
        """Writes the generated header content to a file."""
        with open(self.output_c_header, 'w') as file:
            file.write(header_content)

    def parse_test_group(self, group):
        """To be implemented by subclasses for specific XDH types."""
        raise NotImplementedError

    def parse(self):
        """Iterates through all target files and parses test groups."""
        header_content = self.generate_header_content_start()
        for file in self.target_files:
            file_path = os.path.join(self.directory_path, file)
            try:
                data = self.read_json(file_path)
                test_groups = data.get('testGroups', [])
                for group in test_groups:
                    header_content += self.parse_test_group(group)
            except Exception as e:
                print(f"Failed to process file {file_path}: {e}")
        header_content += self.generate_header_content_end()
        self.write_header(header_content)

    def generate_header_content_start(self):
        """Generates the beginning of the header file. To be implemented by subclasses."""
        raise NotImplementedError

    def generate_header_content_end(self):
        """Generates the end of the header file."""
        return "};\n#endif // TEST_VECTORS_XDH_H\n"

# Standard XDH Parser
class XdhParser(BaseParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from XDH test vectors */\n"
            "#ifndef TEST_VECTORS_XDH_H\n#define TEST_VECTORS_XDH_H\n"
            "#include <stddef.h>\n\n"
            "#define MAX_FLAGS 5\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    unsigned char public_key[56];\n"
            "    size_t public_key_len;\n"
            "    unsigned char private_key[56];\n"
            "    size_t private_key_len;\n"
            "    unsigned char shared[56];\n"
            "    size_t shared_len;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "    const char* flags[MAX_FLAGS];\n"
            "    size_t flags_len;\n"
            "} XdhTestCase;\n\n"
            "static const XdhTestCase xdh_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("curve", "unknown_curve")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            public_key = binascii.unhexlify(test.get("public", "")) if test.get("public") else b""
            private_key = binascii.unhexlify(test.get("private", "")) if test.get("private") else b""
            shared = binascii.unhexlify(test.get("shared", "")) if test.get("shared") else b""
            comment = self.escape_string(test.get("comment", ""))
            flags = test.get("flags", [])
            content += (
                f"    {{ {tc_id}, \"{curve}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in public_key)} }}, {len(public_key)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in private_key)} }}, {len(private_key)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in shared)} }}, {len(shared)}, "
                f"\"{test.get('result', '')}\", \"{comment}\", "
                f"{{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
            )
        return content

# PEM Parser
class XdhPemParser(BaseXDHParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from XDH PEM test vectors */\n"
            "#ifndef TEST_VECTORS_XDH_PEM_H\n#define TEST_VECTORS_XDH_PEM_H\n"
            "#include <stddef.h>\n\n"
            "#define MAX_FLAGS 5\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    const char* public_key_pem;\n"
            "    const char* private_key_pem;\n"
            "    unsigned char shared[56];\n"
            "    size_t shared_len;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "    const char* flags[MAX_FLAGS];\n"
            "    size_t flags_len;\n"
            "} XdhPemTestCase;\n\n"
            "static const XdhPemTestCase xdh_pem_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("curve", "unknown_curve")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            public_pem = self.escape_string(test.get("public", ""))
            private_pem = self.escape_string(test.get("private", ""))
            shared = binascii.unhexlify(test.get("shared", "")) if test.get("shared") else b""
            comment = self.escape_string(test.get("comment", ""))
            flags = test.get("flags", [])
            content += (
                f"    {{ {tc_id}, \"{curve}\", \"{public_pem}\", \"{private_pem}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in shared)} }}, {len(shared)}, "
                f"\"{test.get('result', '')}\", \"{comment}\", "
                f"{{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
            )
        return content

# JWK Parser
class XdhJwkParser(BaseXDHParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from XDH JWK test vectors */\n"
            "#ifndef TEST_VECTORS_XDH_JWK_H\n#define TEST_VECTORS_XDH_JWK_H\n"
            "#include <stddef.h>\n\n"
            "#define MAX_FLAGS 5\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    const char* public_x;\n"
            "    const char* private_d;\n"
            "    unsigned char shared[56];\n"
            "    size_t shared_len;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "    const char* flags[MAX_FLAGS];\n"
            "    size_t flags_len;\n"
            "} XdhJwkTestCase;\n\n"
            "static const XdhJwkTestCase xdh_jwk_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("curve", "unknown_curve")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            public_jwk = test.get("public", {})
            private_jwk = test.get("private", {})
            public_x = self.escape_string(public_jwk.get("x", ""))
            private_d = self.escape_string(private_jwk.get("d", ""))
            shared = binascii.unhexlify(test.get("shared", "")) if test.get("shared") else b""
            comment = self.escape_string(test.get("comment", ""))
            flags = test.get("flags", [])
            content += (
                f"    {{ {tc_id}, \"{curve}\", \"{public_x}\", \"{private_d}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in shared)} }}, {len(shared)}, "
                f"\"{test.get('result', '')}\", \"{comment}\", "
                f"{{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
            )
        return content

# ASN Parser
class XdhAsnParser(BaseXDHParser):
    def generate_header_content_start(self):
        return (
            "/* Auto-generated header file from XDH ASN test vectors */\n"
            "#ifndef TEST_VECTORS_XDH_ASN_H\n#define TEST_VECTORS_XDH_ASN_H\n"
            "#include <stddef.h>\n\n"
            "#define MAX_FLAGS 5\n\n"
            "typedef struct {\n"
            "    int tc_id;\n"
            "    const char* curve;\n"
            "    unsigned char public_key_asn[128];\n"
            "    size_t public_key_asn_len;\n"
            "    unsigned char private_key_asn[128];\n"
            "    size_t private_key_asn_len;\n"
            "    unsigned char shared[56];\n"
            "    size_t shared_len;\n"
            "    const char* result;\n"
            "    const char* comment;\n"
            "    const char* flags[MAX_FLAGS];\n"
            "    size_t flags_len;\n"
            "} XdhAsnTestCase;\n\n"
            "static const XdhAsnTestCase xdh_asn_test_cases[] = {\n"
        )

    def parse_test_group(self, group):
        curve = group.get("curve", "unknown_curve")
        content = ""
        for test in group.get("tests", []):
            tc_id = test.get("tcId", -1)
            public_key_asn = binascii.unhexlify(test.get("public", "")) if test.get("public") else b""
            private_key_asn = binascii.unhexlify(test.get("private", "")) if test.get("private") else b""
            shared = binascii.unhexlify(test.get("shared", "")) if test.get("shared") else b""
            comment = self.escape_string(test.get("comment", ""))
            flags = test.get("flags", [])
            content += (
                f"    {{ {tc_id}, \"{curve}\", "
                f"{{ {', '.join(f'0x{b:02x}' for b in public_key_asn)} }}, {len(public_key_asn)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in private_key_asn)} }}, {len(private_key_asn)}, "
                f"{{ {', '.join(f'0x{b:02x}' for b in shared)} }}, {len(shared)}, "
                f"\"{test.get('result', '')}\", \"{comment}\", "
                f"{{ {', '.join(f'\"{flag}\"' for flag in flags)} }}, {len(flags)} }},\n"
            )
        return content

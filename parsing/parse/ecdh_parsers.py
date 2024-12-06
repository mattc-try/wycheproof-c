import os
import json


class BaseECDHParser:
    def __init__(self, directory_path, output_c_header, target_files):
        self.directory_path = directory_path
        self.output_c_header = output_c_header
        self.target_files = target_files

    def read_json(self, file_path):
        """Reads and parses a JSON file."""
        with open(file_path, 'r') as file:
            return json.load(file)

    def write_header(self, header_content):
        """Writes the generated header content to a file."""
        with open(self.output_c_header, 'w') as file:
            file.write(header_content)

    def parse_test_group(self, group):
        """To be implemented by subclasses for specific ECDH test types."""
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
        """Generates the beginning of the header file."""
        raise NotImplementedError

    def generate_header_content_end(self):
        """Generates the end of the header file."""
        return "};\n\n#endif\n"


# Standard ECDH Parser
class EcdhParser(BaseECDHParser):
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
class EcdhEcPointParser(BaseECDHParser):
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
class EcdhWebCryptoParser(BaseECDHParser):
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

import os
import json
from abc import ABC, abstractmethod

class BaseParser(ABC):
    def __init__(self, directory_path, output_c_header, target_files):
        self.directory_path = directory_path
        self.output_c_header = output_c_header
        self.target_files = target_files

    def escape_string(self, s):
        """Escapes special characters in strings for C headers."""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

    def read_json(self, file_path):
        with open(file_path, 'r') as file:
            return json.load(file)

    def write_header(self, header_content):
        with open(self.output_c_header, 'w') as file:
            file.write(header_content)

    @abstractmethod
    def parse_test_group(self, group):
        pass

    def parse(self):
        header_content = self.generate_header_content_start()
        for file in self.target_files:
            file_path = os.path.join(self.directory_path, file)
            try:
                data = self.read_json(file_path)
                test_groups = data.get("testGroups", [])
                for group in test_groups:
                    header_content += self.parse_test_group(group)
            except Exception as e:
                print(f"Failed to process file {file_path}: {e}")
        header_content += self.generate_header_content_end()
        self.write_header(header_content)

    @abstractmethod
    def generate_header_content_start(self):
        pass

    def generate_header_content_end(self):
        return "};\n\n#endif\n"

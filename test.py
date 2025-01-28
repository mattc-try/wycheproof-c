import os
import subprocess
import time

# Paths and test files configuration
OPENSSL_INCLUDE = "/opt/homebrew/opt/openssl@3/include"
OPENSSL_LIB = "/opt/homebrew/opt/openssl@3/lib"

# Mapping of test sets to their source files and outputs.
# Adjust these based on the actual files you have.
TESTS = {
    "unit": [
        {
            "name": "ecdh_test",
            "source": "tests/unit/ecdh_test.c",
            "output": "ecdh_test_bin"
        },
        {
            "name": "ecdsa_test",
            "source": "tests/unit/ecdsa_test.c",
            "output": "ecdsa_test_bin"
        },
        {
            "name": "eckey_test",
            "source": "tests/unit/eckey_test.c",
            "output": "eckey_test_bin"
        },
        {
            "name": "rsakey_test",
            "source": "tests/unit/rsakey_test.c",
            "output": "rsakey_test_bin"
        },
        {
            "name": "dsa_test",
            "source": "tests/unit/dsa_test.c",
            "output": "dsa_test_bin"
        },
        {
            "name": "rsaoaep_test",
            "source": "tests/unit/rsaoaep_test.c",
            "output": "rsaoaep_test_bin"
        },
        {
            "name": "rsapss_test",
            "source": "tests/unit/rsapss_test.c",
            "output": "rsapss_test_bin"
        },
        {
            "name": "rsasig_test",
            "source": "tests/unit/rsasig_test.c",
            "output": "rsasig_test_bin"
        },
        {
            "name": "securerand_test",
            "source": "tests/unit/securerand_test.c",
            "output": "securerand_test_bin"
        },
    ],
    "vect": [
        {
            "name": "v_ecdh",
            "source": "tests/vect/v_ecdh.c",
            "output": "v_ecdh_test_bin"
        },
        {
            "name": "v_ecdsa",
            "source": "tests/vect/v_ecdsa.c",
            "output": "v_ecdsa_test_bin"
        }, # some failing
        {
            "name": "v_xdh",
            "source": "tests/vect/v_xdh.c",
            "output": "v_xdh_test_bin"
        },
        # {
        #     "name": "v_rsasig",
        #     "source": "tests/vect/v_rsasig.c",
        #     "output": "v_rsasig_test_bin"
        # }, # most failing 
        # {
        #     "name": "v_rsaenc",
        #     "source": "tests/vect/v_rsaenc.c",
        #     "output": "v_rsaenc_test_bin"
        # }, # most failing 
        # {
        #     "name": "v_dsa",
        #     "source": "tests/vect/v_dsa.c",
        #     "output": "v_dsa_test_bin"
        # } # not compiling yet
    ]
}

OUTPUT_DIR = "outputs"

def compile_test(source_file, output_file):
    """Compile a single test source file into an executable."""
    cmd = [
        "gcc",
        source_file,
        "-o",
        os.path.join(OUTPUT_DIR, output_file),
        f"-I{OPENSSL_INCLUDE}",
        f"-L{OPENSSL_LIB}",
        "-lssl",
        "-lcrypto",
        "-Wno-deprecated-declarations"
    ]
    print(f"Compiling: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error compiling {source_file}: {result.stderr}")
        return False
    return True

def run_test(output_file):
    """Run a single test executable and show output in real-time."""
    cmd = [os.path.join(OUTPUT_DIR, output_file)]
    print(f"Running: {cmd[0]}")  # Add separation before running the test
    print("\n\n\n################################# Test Output #################################")  # Add a header for the test output

    # Remove capture_output to see output as it prints
    result = subprocess.run(cmd, text=True)

    print("################################# End Test Output #################################\n\n\n")
    
    if result.returncode != 0:
        print("Some tests failed (non-zero exit code). Check the output above for details.")

if __name__ == "__main__":
    # Prompt user for action
    action = input("Do you want to (1) run tests only or (2) compile and run tests? [1/2]: ").strip()
    while action not in ("1", "2"):
        action = input("Invalid choice. Please enter 1 or 2: ").strip()
    
    # Prompt user for which tests
    test_choice = input("Which tests do you want to target? (all/unit/vect/one): ").strip().lower()
    while test_choice not in ("all", "unit", "vect", "one"):
        test_choice = input("Invalid choice. Please enter 'all', 'unit', 'vect', or 'one': ").strip().lower()

    selected_tests = []

    if test_choice == "all":
        sets_to_run = ["unit", "vect"]
        # Flatten all tests
        for s in sets_to_run:
            selected_tests.extend(TESTS[s])
    elif test_choice == "unit":
        sets_to_run = ["unit"]
        selected_tests = TESTS["unit"]
    elif test_choice == "vect":
        sets_to_run = ["vect"]
        selected_tests = TESTS["vect"]
    else:
        # 'one' chosen: list all tests from both sets and allow user to pick one
        all_tests = TESTS["unit"] + TESTS["vect"]
        print("Available tests:")
        for t in all_tests:
            print(f"- {t['name']}")
        chosen_test_name = input("Please enter the name of the test you want to run: ").strip()

        # Find the test by name
        chosen_test = None
        for t in all_tests:
            if t['name'] == chosen_test_name:
                chosen_test = t
                break

        if chosen_test is None:
            print("Test not found. Exiting.")
            exit(1)

        selected_tests = [chosen_test]

    start_time = time.perf_counter()

    # Compile if needed
    if action == "2":  # compile and run
        # Ensure output directory exists
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
        
        for test in selected_tests:
            success = compile_test(test["source"], test["output"])
            if not success:
                print("Compilation failed, aborting.")
                exit(1)

    # Run tests
    for test in selected_tests:
        binary_path = os.path.join(OUTPUT_DIR, test["output"])
        if not os.path.isfile(binary_path):
            print(f"Test binary not found: {binary_path}. Perhaps you need to compile first.")
            continue
        run_test(test["output"])
    
    end_time = time.perf_counter()
    elapsed = end_time - start_time
    print(f"Operation completed in {elapsed:.2f} seconds.")

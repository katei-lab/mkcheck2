import os
import sys
import subprocess
import argparse
import shutil
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

def print_usage():
    print(f"Usage: {sys.argv[0]} [--update-snapshot]")
    print("")
    print("Options:")
    print("  --update-snapshot  Update the expected output files")

def run_command(command, shell=True):
    print(f"\033[0;36m$ {command}\033[0m")
    subprocess.run(command, shell=shell, check=True)

def run_capturing_command(command, shell=True, check=True):
    result = subprocess.run(command, shell=shell, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode('utf-8'), result.stderr.decode('utf-8'), result

def run_test(test_case, test_suite, tmpdir, update_snapshot):
    test_case_basename: str = os.path.basename(test_case)
    test_case_basename = test_case_basename.removesuffix('.sh')

    expected = os.path.join(test_suite, f"{test_case_basename}.txt")
    actual = os.path.join(tmpdir, f"{test_case_basename}.txt")
    test_case_tmpdir = os.path.join(tmpdir, f"{test_case_basename}.tmp")

    os.makedirs(test_case_tmpdir, exist_ok=True)

    command = f"sudo env t={test_case_tmpdir} utils={os.getcwd()}/.build/debug/mkcheck2-test-utils " \
              f"{os.getcwd()}/.build/debug/mkcheck2 -o {actual} --format ascii -- bash {test_case}"
    
    # Run the command and capture stdout/stderr
    stdout, stderr, _ = run_capturing_command(command)

    snapshot_updated = False

    diff_stdout, diff_stderr, diff_result = run_capturing_command(f"diff -u {expected} {actual}", check=False)
    if diff_result.returncode == 0:
        stdout += f"\033[0;32mTest passed: {test_case}\033[0m\n{command}\n"
    else:
        if update_snapshot:
            shutil.copyfile(actual, expected)
            snapshot_updated = True
            stdout += diff_stdout
        else:
            stderr += f"\033[0;31mTest failed: {test_case}\033[0m\n"
            raise RuntimeError(f"Test failed: {test_case}\n{command}\n{diff_stdout}\nstdout:\n{stdout}\nstderr:\n{stderr}")

    return snapshot_updated, stdout, stderr

def main():
    parser = argparse.ArgumentParser(description='Run tests and update snapshots.')
    parser.add_argument('--update-snapshot', action='store_true', help='Update the expected output files')
    parser.add_argument('--only', action='append', help='Only run the specified test case(s)')
    parser.add_argument('--skip', action='append', help='Skip the specified test case(s)')
    parser.add_argument('--skip-build', action='store_true', help='Skip the initial build commands')
    parser.add_argument('--verbose', action='store_true', help='Print verbose output')
    parser.add_argument('-j', type=int, help='Number of parallel tests to run')
    args = parser.parse_args()

    update_snapshot = args.update_snapshot

    if update_snapshot:
        print("\033[0;33mUpdating snapshots...\033[0m")

    # Run initial build commands
    if not args.skip_build:
        run_command("ninja -C build")
        run_command("touch Sources/mkcheck2/mkcheck2.swift")
        run_command("swift build --product mkcheck2")
        run_command("swift build --product mkcheck2-test-utils")

    test_suite = 'Tests/SnapshotTests'
    tmpdir = f"{test_suite}.tmp"
    
    # Remove and recreate temporary directory
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    os.makedirs(tmpdir, exist_ok=True)

    # Run all tests in parallel using ThreadPoolExecutor
    if args.only:
        test_cases = [os.path.join(test_suite, f"{test_case}.sh") for test_case in args.only]
    else:
        test_cases = [os.path.join(test_suite, test_case) for test_case in os.listdir(test_suite) if test_case.endswith('.sh')]
    
    if args.skip:
        test_cases = [test_case for test_case in test_cases if os.path.basename(test_case) not in args.skip]

    with ProcessPoolExecutor(max_workers=args.j) as executor:
        future_to_test = {executor.submit(run_test, test_case, test_suite, tmpdir, update_snapshot): test_case for test_case in test_cases}

        for future in as_completed(future_to_test):
            test_case = future_to_test[future]
            try:
                snapshot_updated, stdout, stderr = future.result()  # Get the stdout/stderr from the completed test case
                if snapshot_updated:
                    print(f"\033[0;33mUpdated snapshot:\033[0m {test_case}")
                else:
                    print(f"\033[0;32mTest passed:\033[0m {test_case}")
                if snapshot_updated or args.verbose:
                    print(stdout)
                if (snapshot_updated or args.verbose) and stderr:
                    print(stderr, file=sys.stderr)
            except Exception as exc:
                print(f"\033[0;31mTest failed: {test_case}\033[0m\nError: {exc}")

if __name__ == "__main__":
    main()


import argparse
import subprocess
import sys
import os
from typing import List


def traceroute(target: str, progressive: bool, output_file: str):
    """
    Perform a traceroute to a URL or an IP address.

    Args:
        target (str): The traceroute target (URL or IP).
        progressive (bool): If True, display IPs progressively.
        output_file (str): Name of the output file to save the results.
    """
    try:
        # Initialize the traceroute command
        command = ["traceroute", target]
        print(f"Starting traceroute to {target}...\n")

        # Output file management
        file = None
        if output_file:
            file = open(output_file, "w")
            print(f"Results will be saved to {output_file}\n")

        # Progressive execution
        if progressive:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                print(line.strip())
                if file:
                    file.write(line)
            process.wait()
        else:
            # Blocking execution (complete)
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(result.stdout)
            if file:
                file.write(result.stdout)

        # Close the file if used
        if file:
            file.close()

    except FileNotFoundError:
        print("Error: The 'traceroute' command was not found. Ensure it is installed on your system.")
    except PermissionError:
        print("Error: Insufficient permissions to run traceroute.")
    except KeyboardInterrupt:
        print("\nOperation canceled by the user.")
    except Exception as e:
        print(f"An error occurred: {e}")


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Script to perform a traceroute to a target (IP or URL).")
    parser.add_argument("target", type=str, help="The target URL or IP address.")
    parser.add_argument("-p", "--progressive", action="store_true",
                        help="Display IPs progressively during the traceroute.")
    parser.add_argument("-o", "--output-file", type=str, help="Name of the file to save the traceroute results.")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        traceroute(target=args.target, progressive=args.progressive, output_file=args.output_file)
    except Exception as e:
        print(f"Error in main execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

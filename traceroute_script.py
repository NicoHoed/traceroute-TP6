import argparse
import re
import subprocess
import sys


def traceroute(target: str, progressive: bool, output_file: str):
    """
    Perform a traceroute to a URL or an IP address and extract the IPs of the hops.

    Args:
        target (str): The traceroute target (URL or IP).
        progressive (bool): If True, display IPs progressively.
        output_file (str): Name of the output file to save the results.
    """
    # Regular expression to match IPv4 and IPv6 addresses
    ip_pattern = re.compile(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?:[0-9a-fA-F:]+:+)+[0-9a-fA-F:]+\b"
    )

    # Set to store unique IPs
    unique_ips = set()

    try:
        # Initialize the traceroute command
        command = ["traceroute", target]
        print(f"Starting traceroute to {target}...\n")

        # Output file management
        file = None
        if output_file:
            try:
                file = open(output_file, "w")
                print(f"Results will be saved to {output_file}\n")
            except OSError as e:
                print(f"Error opening output file '{output_file}': {e}")
                return

        # Progressive execution
        if progressive:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                # Find IP addresses in each line
                ip_matches = ip_pattern.findall(line)
                for ip in ip_matches:
                    if ip not in unique_ips:
                        unique_ips.add(ip)
                        print(ip)
                        if file:
                            file.write(ip + "\n")
            process.wait()

        else:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                print(f"Traceroute failed: {result.stderr.strip()}")
                return

            # Find IP addresses in the complete output
            ip_matches = ip_pattern.findall(result.stdout)
            if not ip_matches:
                print("No IP addresses found in traceroute output.")
            else:
                for ip in ip_matches:
                    if ip not in unique_ips:
                        unique_ips.add(ip)
                        print(ip)
                        if file:
                            file.write(ip + "\n")

    except FileNotFoundError:
        print("Error: The 'traceroute' command was not found. Ensure it is installed on your system.")
    except PermissionError:
        print("Error: Insufficient permissions to run traceroute.")
    except subprocess.SubprocessError as e:
        print(f"An error occurred while executing traceroute: {e}")
    except KeyboardInterrupt:
        print("\nOperation canceled by the user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if file:
            try:
                file.close()
            except Exception as e:
                print(f"Error closing output file: {e}")


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Perform a traceroute to a target (IP or URL).")
    parser.add_argument("target", type=str, help="The target URL or IP address.")
    parser.add_argument("-p", "--progressive", action="store_true",
                        help="Display IPs progressively during the traceroute.")
    parser.add_argument("-o", "--output-file", type=str, help="Name of the file to save the traceroute results.")
    return parser.parse_args()


def main():
    """
    Main function to execute the traceroute script.
    """
    args = parse_args()
    traceroute(target=args.target, progressive=args.progressive, output_file=args.output_file)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Fatal error in main execution: {e}")
        sys.exit(1)

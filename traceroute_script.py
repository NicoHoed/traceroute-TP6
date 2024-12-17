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
    try:
        # Initialize the traceroute command
        command = ["traceroute", target]
        print(f"Starting traceroute to {target}...\n")

        # Output file management
        file = None
        if output_file:
            file = open(output_file, "w")
            print(f"Results will be saved to {output_file}\n")

        # Regular expression to extract both IPv4 and IPv6 addresses
        # This pattern matches both IPv4 (xxx.xxx.xxx.xxx) and IPv6 (xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx)
        ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?:[0-9a-fA-F:]+:+)+[0-9a-fA-F:]+\b")

        # Set to store unique IPs
        unique_ips = set()

        # Progressive execution
        if progressive:
            # Run the traceroute command and capture output line by line
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                # Find IP addresses in each line
                ip_matches = ip_pattern.findall(line)
                for ip in ip_matches:
                    # Add the IP to the set (automatically handles duplicates)
                    if ip not in unique_ips:
                        print(ip)
                        unique_ips.add(ip)
                        if file:
                            file.write(ip + "\n")
            process.wait()

        else:
            # Run the traceroute command and capture output
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Debug: Check if traceroute executed correctly
            if result.returncode != 0:
                print(f"Traceroute failed: {result.stderr}")
                return

            # Find IP addresses in the complete output
            ip_matches = ip_pattern.findall(result.stdout)
            if not ip_matches:
                print("No IP addresses found in traceroute output.")
            else:
                # Print and write the IPs to file
                for ip in ip_matches:
                    # Add the IP to the set (automatically handles duplicates)
                    if ip not in unique_ips:
                        print(ip)
                        unique_ips.add(ip)
                        if file:
                            file.write(ip + "\n")

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

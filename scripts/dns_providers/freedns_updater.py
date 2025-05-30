import getpass
import sys
import requests

PROVIDER_NAME = "FreeDNS (freedns.afraid.org)"

def update_dns(domain_name, ip_address):
    """
    Updates DNS record for FreeDNS (freedns.afraid.org).
    Prompts for username and password.
    Returns True on success, False on failure.
    """
    print(f"\n--- DNS Update Configuration for {PROVIDER_NAME} ---")
    print(f"Attempting to update domain: {domain_name} to IP: {ip_address}")

    username = input(f"Enter FreeDNS username for domain '{domain_name}': ").strip()
    if not username:
        print("Username not provided. Skipping FreeDNS update.")
        return False

    # Use getpass for password to avoid echoing to terminal
    password = getpass.getpass(f"Enter FreeDNS password for user '{username}': ").strip()
    if not password:
        print("Password not provided. Skipping FreeDNS update.")
        return False

    # DynDNS v2 protocol URL structure for freedns.afraid.org
    # It's important to use HTTP or HTTPS as supported by the provider for this endpoint.
    # The user previously indicated an HTTP endpoint: http://[USERNAME]:[PASSWORD]@freedns.afraid.org/nic/update?hostname=[DOMAIN]&myip=[IP]
    # We will use the requests library's auth parameter for basic authentication.
    update_url = f"http://freedns.afraid.org/nic/update?hostname={domain_name}&myip={ip_address}"
    # If HTTPS is preferred and supported by freedns.afraid.org for this endpoint:
    # update_url = f"https://freedns.afraid.org/nic/update?hostname={domain_name}&myip={ip_address}"


    print(f"Contacting FreeDNS update URL (credentials hidden)...")
    try:
        response = requests.get(update_url, auth=(username, password), timeout=30)
        
        # No need to explicitly call response.raise_for_status() if we check content,
        # as some non-200 responses from DynDNS services are informational (e.g., "nochg").
        
        response_text = response.text.strip()
        print(f"FreeDNS server response: \"{response_text}\" (Status Code: {response.status_code})")

        # DynDNS v2 protocol specific success responses
        if response_text.lower().startswith("good") or response_text.lower().startswith("nochg"):
            print(f"DNS update for '{domain_name}' via {PROVIDER_NAME} successful or IP was already current.")
            return True
        # Handle common error responses explicitly for better user feedback
        elif response_text.lower().startswith("badauth"):
            print(f"Error: DNS update failed - Bad Authentication. Please check your FreeDNS username and password.")
            return False
        elif response_text.lower().startswith("nohost"):
            print(f"Error: DNS update failed - Hostname '{domain_name}' not found or not configured for dynamic DNS with your account.")
            return False
        elif response_text.lower().startswith("abuse"):
            print(f"Error: DNS update failed - Username '{username}' is blocked due to abuse.")
            return False
        elif response_text.lower().startswith("!donator"):
            print(f"Error: DNS update failed - Request includes a feature not available to general users (e.g., wildcard).")
            return False
        elif response_text.lower().startswith("notfqdn"):
            print(f"Error: DNS update failed - Hostname '{domain_name}' is not a fully-qualified domain name.")
            return False
        else: # Catch-all for other responses that aren't explicitly "good" or "nochg"
            print(f"DNS update for '{domain_name}' via {PROVIDER_NAME} may have failed or had an unexpected response.")
            return False

    except requests.exceptions.Timeout:
        print(f"Error: Timeout connecting to FreeDNS server for {domain_name}.")
        return False
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to FreeDNS server. Check network or if endpoint '{update_url}' is correct.")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error during FreeDNS update for {domain_name}: {e}")
        return False
    except Exception as e: # Catch any other unexpected errors
        print(f"An unexpected error occurred during FreeDNS update: {e}")
        return False

if __name__ == '__main__':
    # Example usage for testing this script directly
    # python scripts/dns_providers/freedns_updater.py yourdomain.example.com 1.2.3.4
    if len(sys.argv) == 3:
        test_domain = sys.argv[1]
        test_ip = sys.argv[2]
        print(f"Testing FreeDNS updater with domain: {test_domain}, IP: {test_ip}")
        update_dns(test_domain, test_ip)
    else:
        print("To test this script directly, run:")
        print("python freedns_updater.py <your_domain> <test_ip>")
        print("You will be prompted for credentials.")

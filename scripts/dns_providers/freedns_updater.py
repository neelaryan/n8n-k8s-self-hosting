"""
This script updates DNS records for FreeDNS (freedns.afraid.org).
It prompts the user for their FreeDNS username and password and uses the
DynDNS v2 protocol to update the IP address for a specified domain.
"""
import getpass
import sys
import requests

PROVIDER_NAME = "FreeDNS (freedns.afraid.org)"


def _get_credentials(domain_name: str) -> tuple[str | None, str | None]:
    """Prompts the user for FreeDNS username and password."""
    username = input(f"Enter FreeDNS username for domain '{domain_name}': ").strip()
    if not username:
        print("Username not provided. Skipping FreeDNS update.")
        return None, None

    password = getpass.getpass(f"Enter FreeDNS password for user '{username}': ").strip()
    if not password:
        print("Password not provided. Skipping FreeDNS update.")
        return None, None
    return username, password


def _handle_freedns_response(
    response_text: str, domain_name: str, username: str
) -> bool:
    """
    Parses the FreeDNS server response and prints appropriate messages.
    Returns True for success, False otherwise.
    """
    response_lower = response_text.lower()

    if response_lower.startswith("good") or response_lower.startswith("nochg"):
        print(
            f"DNS update for '{domain_name}' via {PROVIDER_NAME} "
            f"successful or IP was already current."
        )
        return True

    error_messages = {
        "badauth": "Error: DNS update failed - Bad Authentication. "
                   "Please check your FreeDNS username and password.",
        "nohost": f"Error: DNS update failed - Hostname '{domain_name}' not found or "
                  f"not configured for dynamic DNS with your account.",
        "abuse": f"Error: DNS update failed - Username '{username}' is blocked due to abuse.",
        "!donator": "Error: DNS update failed - Request includes a feature not available "
                    "to general users (e.g., wildcard).",
        "notfqdn": f"Error: DNS update failed - Hostname '{domain_name}' is not "
                   f"a fully-qualified domain name."
    }

    for prefix, message in error_messages.items():
        if response_lower.startswith(prefix):
            print(message)
            return False

    # Default/fallback for unknown non-success responses
    print(
        f"DNS update for '{domain_name}' via {PROVIDER_NAME} "
        f"may have failed or had an unexpected response: {response_text}"
    )
    return False


def update_dns(domain_name: str, ip_address: str) -> bool:
    """
    Updates DNS record for FreeDNS (freedns.afraid.org).
    Prompts for username and password.
    Returns True on success, False on failure.
    """
    print(f"\n--- DNS Update Configuration for {PROVIDER_NAME} ---")
    print(f"Attempting to update domain: {domain_name} to IP: {ip_address}")

    username, password = _get_credentials(domain_name)
    if not username or not password:
        return False

    # DynDNS v2 protocol URL structure for freedns.afraid.org
    base_url = "http://freedns.afraid.org/nic/update"
    update_url = (
        f"{base_url}?hostname={domain_name}"
        f"&myip={ip_address}"
    )
    # If HTTPS is preferred and supported:
    # base_url_https = "https://freedns.afraid.org/nic/update"
    # update_url = (
    # f"{base_url_https}?hostname={domain_name}"
    # f"&myip={ip_address}"
    # )

    print("Contacting FreeDNS update URL (credentials hidden)...")
    try:
        response = requests.get(update_url, auth=(username, password), timeout=30)
        response_text = response.text.strip()
        print(
            f"FreeDNS server response: \"{response_text}\" "
            f"(Status Code: {response.status_code})"
        )
        return _handle_freedns_response(response_text, domain_name, username)

    except requests.exceptions.Timeout:
        print(f"Error: Timeout connecting to FreeDNS server for {domain_name}.")
        return False
    except requests.exceptions.ConnectionError:
        print(
            f"Error: Could not connect to FreeDNS server. "
            f"Check network or if endpoint '{update_url}' is correct."
        )
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error during FreeDNS update for {domain_name}: {e}")
        return False
    except RuntimeError as e: # Catch any other unexpected runtime errors
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

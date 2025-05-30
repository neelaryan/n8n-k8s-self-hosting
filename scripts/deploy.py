"""
Deployment script for n8n on Kubernetes.
Handles resource deployment, DNS updates, and component management.
"""

import sys
import argparse
import base64
import getpass
import types
from pathlib import Path

# Import helper functions
from deployment_helpers import (
    run_kubectl_command,
    delete_resource_if_force,
    delete_namespace_if_force,
    wait_for_resource,
    get_ingress_ip,
    process_yaml_template,
    process_n8n_deployment_env,
    cleanup_temp_yamls
)

# Add project root to sys.path for robust module discovery (e.g., for dynamic imports).
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# --- Configuration ---
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
INFRA_DIR = BASE_DIR / "infra"
N8N_NAMESPACE = "n8n"  # Default Kubernetes namespace for n8n resources
TEMP_YAML_DIR = SCRIPT_DIR / ".tmp_yamls"  # For processed YAMLs

# Dynamically import DNS providers
DNS_PROVIDERS: dict[int, types.ModuleType] = {}
dns_provider_path = SCRIPT_DIR / "dns_providers"
if dns_provider_path.is_dir():
    original_sys_path = list(sys.path)
    sys.path.insert(0, str(BASE_DIR))
    for f_path in dns_provider_path.glob("*.py"):
        if f_path.name == "__init__.py":
            continue
        MODULE_NAME_IMPORT = f"scripts.dns_providers.{f_path.stem}"
        try:
            module = __import__(MODULE_NAME_IMPORT, fromlist=[f_path.stem])
            if hasattr(module, 'PROVIDER_NAME') and hasattr(module, 'update_dns'):
                DNS_PROVIDERS[len(DNS_PROVIDERS) + 1] = module
                print(f"Loaded DNS Provider: {module.PROVIDER_NAME}")
            else:
                WARNING_MESSAGE = (
                    f"Warning: DNS provider module {f_path.name} missing "
                    f"PROVIDER_NAME or update_dns function."
                )
                print(WARNING_MESSAGE)
        except ImportError as e:
            print(f"Warning: Could not import DNS provider {f_path.name}: {e}")
        except AttributeError as e:
            print(f"Warning: Error loading DNS provider {f_path.name} (AttributeError): {e}")
        except TypeError as e:
            print(f"Warning: Error loading DNS provider {f_path.name} (TypeError): {e}")
        except ValueError as e:
            print(f"Warning: Error loading DNS provider {f_path.name} (ValueError): {e}")
    sys.path = original_sys_path
else:
    WARNING_MSG = (
        f"Warning: dns_providers directory not found at {dns_provider_path}. "
        "DNS update functionality will be limited."
    )
    print(WARNING_MSG)

# --- Component Deployment Functions ---
def deploy_namespace_component(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    """
    Deploys the Kubernetes namespace for n8n, optionally deleting it first if the force flag is set.

    Args:
        args: argparse.Namespace: Parsed command-line arguments.
        paths: dict[str, Path]: Dictionary containing paths to YAML files.
    """
    print("\n--- Deploying Namespace ---")
    if args.force:
        delete_namespace_if_force(args.force, N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["namespace"])])

def deploy_storage_component(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    """
    Deploys the storage components required for n8n,
    including persistent volume claims and storage class.

    Args:
        args: argparse.Namespace: Parsed command-line arguments.
        paths: dict[str, Path]: Dictionary containing paths to YAML files.
    """
    print("\n--- Deploying Storage ---")
    if args.force:
        delete_resource_if_force(
            args.force,
            "persistentvolumeclaim",
            "postgresql-pv",
            N8N_NAMESPACE
        )
        delete_resource_if_force(args.force, "persistentvolumeclaim", "n8n-claim0", N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["storage_class"])])
    run_kubectl_command(["apply", "-f", str(paths["pg_pvc"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["n8n_pvc"])], namespace=N8N_NAMESPACE)

def deploy_postgres_component(
    args: argparse.Namespace,
    paths: dict[str, Path],
    pg_user_val: str,
    pg_password_val: str
) -> None:
    """
    Deploys the PostgreSQL components, including secrets, configmap, deployment, and service, 
    with the provided PostgreSQL username and password.

    Args:
        args: argparse.Namespace: Parsed command-line arguments.
        paths: dict[str, Path]: Dictionary containing paths to YAML files and templates.
        pg_user_val (str): PostgreSQL application username.
        pg_password_val (str): PostgreSQL application password.
    """
    print("\n--- Deploying PostgreSQL ---")
    b64_pg_app_user: str = base64.b64encode(pg_user_val.encode('utf-8')).decode('utf-8')
    b64_pg_app_password: str = base64.b64encode(pg_password_val.encode('utf-8')).decode('utf-8')
    pg_secret_replacements: dict[str, str] = {
        "BASE64_PG_APP_USER": b64_pg_app_user,
        "BASE64_PG_APP_PASSWORD": b64_pg_app_password
    }
    processed_pg_secret_yaml: Path = process_yaml_template(
        paths["pg_secret_template"],
        TEMP_YAML_DIR / "postgres-secret.yaml",
        pg_secret_replacements,
        TEMP_YAML_DIR
    )

    if args.force:
        delete_resource_if_force(args.force, "secret", "postgres-secret", N8N_NAMESPACE)
        delete_resource_if_force(
            args.force,
            "configmap",
            "init-data",
            N8N_NAMESPACE
        ) # PG ConfigMap name
        delete_resource_if_force(args.force, "deployment", "postgres", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "service", "postgres-service", N8N_NAMESPACE)

    run_kubectl_command(["apply", "-f", str(processed_pg_secret_yaml)], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["pg_configmap"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["pg_deployment"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["pg_service"])], namespace=N8N_NAMESPACE)
    if not wait_for_resource("deployment/postgres", N8N_NAMESPACE):
        sys.exit(1)

def deploy_n8n_app_component(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    """
    Deploys the n8n application components, including the service and deployment, 
    with environment variables set for the specified domain.

    Args:
        args: argparse.Namespace: Parsed command-line arguments.
        paths: dict[str, Path]: Dictionary containing paths to YAML files and templates.
    """
    print("\n--- Deploying n8n Application ---")
    processed_n8n_deployment_yaml: Path = process_n8n_deployment_env(
        paths["n8n_deployment_template"],
        TEMP_YAML_DIR / "n8n-deployment.yaml",
        args.domain,
        TEMP_YAML_DIR
    )
    if args.force:
        delete_resource_if_force(args.force, "service", "n8n", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "deployment", "n8n", N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["n8n_service"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(
        ["apply", "-f", str(processed_n8n_deployment_yaml)],
        namespace=N8N_NAMESPACE
    )
    if not wait_for_resource("deployment/n8n", N8N_NAMESPACE):
        sys.exit(1)

def deploy_ingress_component(
    args: argparse.Namespace,
    paths: dict[str, Path]
) -> None:
    """
    Deploys the Ingress stack, including ManagedCertificate,
    FrontendConfig, and Ingress resources, with proper ordering
    and optional forced deletion of existing resources.

    Args:
        args: argparse.Namespace: Parsed command-line arguments.
        paths: dict[str, Path]: Dictionary containing paths to YAML files and templates.
    """
    print("\n--- Deploying Ingress Stack (ManagedCertificate, FrontendConfig, Ingress) ---")

    # Prepare domain replacements for template processing
    domain_replacements = {"TARGET_DOMAIN": str(args.domain)}

    # Process templates for each component
    processed_managed_cert_yaml = process_yaml_template(
        paths["managed_cert_template"],
        TEMP_YAML_DIR / "n8n-managed-certificate.yaml",
        domain_replacements,
        TEMP_YAML_DIR
    )

    processed_ingress_yaml = process_yaml_template(
        paths["ingress_template"],
        TEMP_YAML_DIR / "n8n-ingress-tls.yaml",
        domain_replacements,
        TEMP_YAML_DIR
    )

    # FrontendConfig is static, no processing needed
    frontend_config_path = paths["frontend_config"]

    if args.force:
        # Delete in reverse order of dependency
        delete_resource_if_force(
            args.force,
            "ingress",
            "n8n-ingress",
            N8N_NAMESPACE,
        )
        delete_resource_if_force(
            args.force,
            "managedcertificate",
            "n8n-managed-cert",
            N8N_NAMESPACE,
            check_kubectl_errors=False,
        )
        delete_resource_if_force(
            args.force,
            "frontendconfig",
            "n8n-frontend-config",
            N8N_NAMESPACE,
            check_kubectl_errors=False,
        )

    # Apply in order of dependency
    print("Applying FrontendConfig (n8n-frontend-config)...")
    run_kubectl_command(
        ["apply", "-f", str(frontend_config_path)],
        namespace=N8N_NAMESPACE,
    )

    print("Applying ManagedCertificate (n8n-managed-cert)...")
    run_kubectl_command(
        ["apply", "-f", str(processed_managed_cert_yaml)],
        namespace=N8N_NAMESPACE,
    )

    print("Applying Ingress (n8n-ingress)...")
    run_kubectl_command(
        ["apply", "-f", str(processed_ingress_yaml)],
        namespace=N8N_NAMESPACE,
    )

def perform_dns_update_component(
    args: argparse.Namespace,
    ingress_name_for_ip: str = "n8n-ingress"
) -> tuple[str | None, str, types.ModuleType | None]:
    """
    Handles DNS update for the provided domain using the selected DNS provider,
    after retrieving the Ingress IP.
    """
    print("\n--- Ingress IP & DNS Update ---")
    ingress_ip: str | None = get_ingress_ip(
        ingress_name_for_ip,
        N8N_NAMESPACE
    )
    selected_provider_module: types.ModuleType | None = None
    choice_str_local: str = ""

    if args.update_dns and ingress_ip:
        if not DNS_PROVIDERS:
            msg = (
                "No DNS providers found/loaded. "
                "Skipping DNS update."
            )
            print(msg)
            return ingress_ip, choice_str_local, selected_provider_module

        print("\nSelect DNS Provider for Update:")
        for idx, provider_module_item in DNS_PROVIDERS.items():
            provider_name = provider_module_item.PROVIDER_NAME  # type: ignore
            print(f"  {idx}. {provider_name}")

        try:
            prompt = (
                "Enter number of DNS provider "
                "(or press Enter to skip): "
            )
            choice_str_local = input(prompt).strip()

            if not choice_str_local:
                print("Skipping DNS update by user choice.")
                return ingress_ip, choice_str_local, selected_provider_module

            choice: int = int(choice_str_local)
            selected_provider_module = DNS_PROVIDERS.get(choice)

            if not selected_provider_module:
                print("Invalid choice. Skipping DNS update.")
                return ingress_ip, choice_str_local, selected_provider_module

            provider_name = selected_provider_module.PROVIDER_NAME  # type: ignore
            print(f"Proceeding with {provider_name}...")

            update_success: bool = selected_provider_module.update_dns(  # type: ignore
                args.domain,
                ingress_ip
            )
            if not update_success:
                warning_msg = (
                    "Warning: DNS update for "
                    f"{args.domain} via {provider_name} "
                    "might have failed."
                )
                print(warning_msg)

        except ValueError:
            print(
                "Invalid input (not a number). "
                "Skipping DNS update."
            )
    elif args.update_dns and not ingress_ip:
        print(
            "DNS update skipped: Could not obtain "
            f"Ingress IP for {args.domain}."
        )
    return ingress_ip, choice_str_local, selected_provider_module

# --- Main Orchestration Helpers ---
def _parse_arguments_and_determine_actions() -> tuple[argparse.Namespace, dict[str, bool]]:
    """
    Parses command-line arguments and determines which deployment actions to run.
    Returns parsed arguments and a dictionary of actions to perform.
    """
    parser = argparse.ArgumentParser(
        description="Deploy n8n to GKE with Python.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force delete existing resources for selected components."
    )
    parser.add_argument(
        "--domain",
        type=str,
        help="Target domain (e.g., n8n.example.com). Required for n8n, ingress, dns."
    )

    # Component Selection Arguments
    comp_group_title = 'Component Selection (default is --deploy-all if none specified)'
    comp_group = parser.add_argument_group(comp_group_title)
    comp_group.add_argument(
        "--deploy-all",
        action="store_true",
        help="Deploy all components."
    )
    comp_group.add_argument(
        "--deploy-namespace",
        action="store_true",
        help="Deploy/Redeploy Namespace."
    )
    comp_group.add_argument(
        "--deploy-storage",
        action="store_true",
        help="Deploy/Redeploy Storage."
    )
    comp_group.add_argument(
        "--deploy-postgres",
        action="store_true",
        help="Deploy/Redeploy PostgreSQL."
    )
    comp_group.add_argument(
        "--deploy-n8n",
        action="store_true",
        help="Deploy/Redeploy n8n application."
    )
    comp_group.add_argument(
        "--deploy-ingress",
        action="store_true",
        help="Deploy/Redeploy Ingress stack."
    )

    # DNS Update Options
    dns_group = parser.add_argument_group('DNS Update Options')
    dns_group.add_argument(
        "--update-dns",
        action="store_true",
        help="Enable DNS update after relevant components are deployed."
    )
    dns_group.add_argument(
        "--update-dns-only",
        action="store_true",
        help="Only perform DNS update (requires Ingress IP)."
    )

    # PostgreSQL Options
    pg_group_title = 'PostgreSQL Options (used if deploying PostgreSQL)'
    pg_group = parser.add_argument_group(pg_group_title)
    pg_group.add_argument(
        "--pg-user",
        type=str,
        default="n8n",
        help="PostgreSQL application username."
    )
    args: argparse.Namespace = parser.parse_args()

    # Determine which actions to run
    actions_to_run: dict[str, bool] = {
        "namespace": args.deploy_namespace,
        "storage": args.deploy_storage,
        "postgres": args.deploy_postgres,
        "n8n": args.deploy_n8n,
        "ingress": args.deploy_ingress,
        "dns": args.update_dns_only
    }
    any_component_flag_set = any(
        v for k, v in actions_to_run.items() if k != "dns"
    )

    # Handle --deploy-all or no flags case
    if args.deploy_all or not any_component_flag_set:
        deploy_components = ["namespace", "storage", "postgres", "n8n", "ingress"]
        for key in deploy_components:
            actions_to_run[key] = True
        if args.update_dns:  # If --update-dns was with --deploy-all or no flags
            actions_to_run["dns"] = True

    # Validate domain requirement
    domain_required = (
        actions_to_run["n8n"] or
        actions_to_run["ingress"] or
        actions_to_run["dns"] or
        args.update_dns
    )
    if domain_required and not args.domain:
        parser.error(
            "--domain is required if deploying n8n, ingress, "
            "or performing DNS update."
        )

    return args, actions_to_run

def _get_and_validate_yaml_paths() -> tuple[dict[str, Path], dict[str, Path]]:
    """
    Defines and validates paths to static and template YAML files.
    Returns tuple of static and template YAML path dictionaries.
    """
    static_yamls = {
        "namespace": INFRA_DIR / "namespace.yaml",
        "storage_class": INFRA_DIR / "storage" / "storage.yaml",
        "pg_pvc": (
            INFRA_DIR / "postgres" /
            "postgres-claim0-persistentvolumeclaim.yaml"
        ),
        "pg_configmap": INFRA_DIR / "postgres" / "postgres-configmap.yaml",
        "pg_deployment": INFRA_DIR / "postgres" / "postgres-deployment.yaml",
        "pg_service": INFRA_DIR / "postgres" / "postgres-service.yaml",
        "n8n_pvc": (
            INFRA_DIR / "n8n" /
            "n8n-claim0-persistentvolumeclaim.yaml"
        ),
        "n8n_service": INFRA_DIR / "n8n" / "n8n-service.yaml",
        "frontend_config": (
            INFRA_DIR / "n8n" /
            "n8n-ingress-frontend.yaml"
        ),
    }

    template_yamls = {
        "pg_secret_template": (
            INFRA_DIR / "postgres" /
            "postgres-secret.yaml.template"
        ),
        "n8n_deployment_template": (
            INFRA_DIR / "n8n" /
            "n8n-deployment.yaml.template"
        ),
        "managed_cert_template": (
            INFRA_DIR / "n8n" /
            "n8n-managed-certificate.yaml.template"
        ),
        "ingress_template": (
            INFRA_DIR / "n8n" /
            "n8n-ingress-tls.yaml.template"
        ),
    }

    # Validate all paths exist
    for name, path_item in {**static_yamls, **template_yamls}.items():
        if not path_item.exists():
            msg = f"Error: Required YAML file '{name}' not found at {path_item}"
            print(msg)
            sys.exit(1)

    return static_yamls, template_yamls

def _deploy_selected_components(
    args: argparse.Namespace,
    actions_to_run: dict[str, bool],
    static_yamls: dict[str, Path],
    template_yamls: dict[str, Path]
) -> str | None:
    """
    Orchestrates the deployment of selected components.
    Returns the PostgreSQL password if it was set during deployment.
    """
    combined_yamls = {**static_yamls, **template_yamls}
    pg_password_val: str | None = None

    if actions_to_run["namespace"]:
        deploy_namespace_component(args, static_yamls)

    if actions_to_run["storage"]:
        deploy_storage_component(args, static_yamls)

    if actions_to_run["postgres"]:
        prompt_msg = f"Enter PostgreSQL password for user '{args.pg_user}': "
        pg_password_val = getpass.getpass(prompt_msg).strip()

        if not pg_password_val:
            print("PostgreSQL password not provided. Exiting.")
            sys.exit(1)

        deploy_postgres_component(
            args,
            combined_yamls,
            args.pg_user,
            pg_password_val
        )

    if actions_to_run["n8n"]:
        deploy_n8n_app_component(args, combined_yamls)

    if actions_to_run["ingress"]:
        deploy_ingress_component(args, combined_yamls)

    return pg_password_val

def _handle_dns_update_flow(
    args: argparse.Namespace,
    actions_to_run: dict[str, bool]
) -> tuple[str | None, str, types.ModuleType | None]:
    """
    Manages the DNS update process based on arguments and deployment status.
    Returns the ingress IP, user's choice string, and selected DNS provider.
    """
    ingress_ip: str | None = None
    choice_str: str = ""
    selected_provider: types.ModuleType | None = None

    # Check if any deployment component was selected
    deploy_components = [
        "namespace", "storage", "postgres", "n8n", "ingress"
    ]
    any_component_flag_set_for_dns_check = any(
        actions_to_run[comp] for comp in deploy_components
    )

    # Determine if DNS update should be performed
    should_perform_dns_update = (
        actions_to_run["dns"] or  # --update-dns-only
        (args.update_dns and any_component_flag_set_for_dns_check)
    )

    if should_perform_dns_update:
        if not args.domain:
            print("Error: --domain is required for DNS update.")
        else:
            dns_update_result = perform_dns_update_component(args)
            ingress_ip, choice_str, selected_provider = dns_update_result

    return ingress_ip, choice_str, selected_provider

def _print_final_summary(
    args: argparse.Namespace,
    actions_to_run: dict[str, bool],
    ingress_ip: str | None,
    choice_str: str,
    selected_provider: types.ModuleType | None
) -> None:
    """Prints a summary of the deployment process and next steps."""
    print("\n---------------------------------------------------------------------")
    print("Deployment script finished.")
    if args.domain:
        print(f"n8n should eventually be accessible at: https://{args.domain}")

    if ingress_ip:
        print(f"The Ingress IP is: {ingress_ip}.")
        # Check if a DNS update was attempted:
        # 1. --update-dns or --update-dns-only was specified.
        # 2. DNS providers are available.
        # 3. A choice for a provider was made (choice_str is not empty).
        # 4. A provider module was actually selected.
        dns_update_attempted = (
            (args.update_dns or actions_to_run["dns"]) and
            DNS_PROVIDERS and choice_str and selected_provider
        )
        if dns_update_attempted:
            print(f"Ensure DNS for {args.domain} has propagated to this IP.")
        else:
            # This 'else' covers cases where DNS update was intended but skipped
            # or not intended at all but an IP was found.
            if args.update_dns or actions_to_run["dns"]: # If DNS update was intended
                manual_dns_msg = (
                    f"Please manually point DNS A record for {args.domain} to this IP "
                    "if not updated by the script."
                )
                print(manual_dns_msg)
    elif args.update_dns or actions_to_run["dns"]: # If DNS update was intended but no IP
        print(
            f"Could not determine Ingress IP for {args.domain}. "
            "DNS update could not be performed."
        )
        print(
            f"Check GKE console for Load Balancer IP and manually update DNS for {args.domain}."
        )

    if actions_to_run["ingress"] or actions_to_run["n8n"]:
        ssl_msg = (
            "Google-managed SSL certificate provisioning may take several minutes "
            "after DNS propagation and Ingress setup."
        )
        print(ssl_msg)
    print("---------------------------------------------------------------------")

# --- Main Orchestration ---
def main() -> None:
    """
    Main function to orchestrate the deployment of n8n to GKE.
    It parses arguments, validates inputs, deploys selected components,
    optionally updates DNS records, and cleans up temporary files.
    """
    args, actions_to_run = _parse_arguments_and_determine_actions()
    static_yamls, template_yamls = _get_and_validate_yaml_paths()

    print(f"Starting n8n GKE deployment for domain: {args.domain if args.domain else 'N/A'}...")
    if args.force:
        print("Force mode enabled for selected components.")

    if TEMP_YAML_DIR.exists() and args.force:
        cleanup_temp_yamls(TEMP_YAML_DIR)
    TEMP_YAML_DIR.mkdir(parents=True, exist_ok=True)

    ingress_ip_final: str | None = None
    choice_str_final: str = ""
    selected_provider_final: types.ModuleType | None = None

    try:
        _deploy_selected_components(
            args, actions_to_run, static_yamls, template_yamls
        )
        ingress_ip_final, choice_str_final, selected_provider_final = (
            _handle_dns_update_flow(args, actions_to_run)
        )
    finally:
        cleanup_temp_yamls(TEMP_YAML_DIR)

    _print_final_summary(
        args, actions_to_run, ingress_ip_final, choice_str_final, selected_provider_final
    )

if __name__ == "__main__":
    main()

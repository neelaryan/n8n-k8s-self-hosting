import subprocess
import argparse
import time
import sys
from pathlib import Path
import base64
import getpass
import shutil # For cleaning up .tmp_yamls
import types # For ModuleType hinting
from typing import Any # For Any type hinting
import yaml  # PyYAML

# --- Configuration & Imports ---
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
INFRA_DIR = BASE_DIR / "infra"
N8N_NAMESPACE = "n8n" # Default Kubernetes namespace for n8n resources
TEMP_YAML_DIR = SCRIPT_DIR / ".tmp_yamls" # For processed YAMLs

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
                print(f"Warning: DNS provider module {f_path.name} missing PROVIDER_NAME or update_dns function.")
        except ImportError as e:
            print(f"Warning: Could not import DNS provider {f_path.name}: {e}")
        except Exception as e:
            print(f"Warning: Error loading DNS provider {f_path.name}: {e}")
    sys.path = original_sys_path
else:
    print(f"Warning: dns_providers directory not found at {dns_provider_path}. DNS update functionality will be limited.")

# --- Helper Functions ---
def run_command(command_args: list[str], check: bool = True, capture_output: bool = False, text: bool = True, exec_config: dict[str, Any] | None = None) -> bool | str:
    """
    Executes a shell command using subprocess.run and handles common cases.

    Args:
        command_args (list): The command and its arguments.
        check (bool): If True, raises CalledProcessError for non-zero exit codes.
        capture_output (bool): If True, captures stdout and returns it.
        text (bool): If True, decodes stdout/stderr as text.
        exec_config (dict, optional): Advanced execution configurations.
            'shell' (bool): Whether to use the shell (default: False).
            'working_dir' (str/Path, optional): Directory to run in (default: None).
            'timeout' (int, optional): Command timeout in seconds (default: 360).

    Returns:
        bool | str: True on success (if not capturing output),
                     stdout string (if capturing output),
                     False on failure if check is False.
    """
    print(f"Executing: {' '.join(command_args)}")

    cfg: dict[str, Any] = exec_config if exec_config else {}
    use_shell: bool = bool(cfg.get('shell', False)) # Ensure bool
    use_working_dir: str | Path | None = cfg.get('working_dir') # type: ignore
    cmd_timeout: int = int(cfg.get('timeout', 360)) # Ensure int

    try:
        process = subprocess.run(
            command_args,
            check=check,
            capture_output=capture_output,
            text=text,
            shell=use_shell,
            cwd=use_working_dir,
            timeout=cmd_timeout
        )
        if capture_output:
            if process.stdout:
                return process.stdout.strip()
            else:
                return ""
        return True
    except subprocess.TimeoutExpired:
        print(f"Error: Command timed out - {' '.join(command_args)}")
        if check:
            sys.exit(1)
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(command_args)}\nReturn code: {e.returncode}")
        if e.stdout:
            print(f"Stdout: {e.stdout.strip()}")
        if e.stderr:
            print(f"Stderr: {e.stderr.strip()}")
        if check:
            sys.exit(1)
        return False
    except FileNotFoundError:
        print(f"Error: Command not found - {command_args[0]}. Is kubectl in your PATH?")
        if check:
            sys.exit(1)
        return False

def run_kubectl_command(kubectl_args: list[str], namespace: str | None = None, check: bool = True, capture_output: bool = False) -> bool | str:
    """
    Executes a kubectl command with optional namespace settings.

    Args:
        kubectl_args (list[str]): The kubectl command arguments.
        namespace (str, optional): The Kubernetes namespace to target.
        check (bool, optional): Whether to raise an error on failure.
        capture_output (bool, optional): Whether to capture and return the command output.

    Returns:
        bool | str: True on success or the command output if capture_output is True.
    """
    cmd: list[str] = ["kubectl"] + kubectl_args
    if namespace:
        cmd.extend(["-n", namespace])
    return run_command(cmd, check=check, capture_output=capture_output)

def delete_resource_if_force(force_flag: bool, resource_type: str, resource_name: str, namespace: str | None = None, check_kubectl_errors: bool = False) -> None:
    """
    Delete a Kubernetes resource if the force flag is enabled.

    Args:
        force_flag (bool): Flag indicating whether to force deletion.
        resource_type (str): The type of Kubernetes resource.
        resource_name (str): The name of the Kubernetes resource.
        namespace (str, optional): The namespace where the resource resides.
        check_kubectl_errors (bool, optional): Option to check for errors in the kubectl command.
    """
    if force_flag:
        print(f"Force mode: Deleting {resource_type} {resource_name}" + (f" in namespace {namespace}" if namespace else ""))
        run_kubectl_command(["delete", resource_type, resource_name, "--ignore-not-found=true"], namespace=namespace, check=check_kubectl_errors)

def delete_namespace_if_force(force_flag: bool, namespace_to_delete: str) -> None:
    """
    Deletes the specified namespace if the force flag is enabled.
    """
    if force_flag:
        print(f"Force mode: Deleting namespace {namespace_to_delete}...")
        run_kubectl_command(["delete", "namespace", namespace_to_delete, "--ignore-not-found=true"], check=False)
        print(f"Waiting for namespace {namespace_to_delete} to be terminated (up to ~60s)...")
        for i in range(12):
            time.sleep(5)
            ns_exists_output = run_kubectl_command(["get", "namespace", namespace_to_delete, "--ignore-not-found", "-o", "name"], check=False, capture_output=True)
            if not ns_exists_output:
                print(f"Namespace {namespace_to_delete} terminated.")
                return
            if i == 5 :
                print(f"Still waiting for namespace {namespace_to_delete} to terminate...")
        print(f"Warning: Namespace {namespace_to_delete} might still be terminating after 60s.")

def wait_for_resource(resource_type_name: str, namespace: str, condition: str = "Available", timeout_seconds: int = 300) -> bool:
    """
    Waits until the specified Kubernetes resource reaches the desired condition within a timeout period.
    
    Args:
        resource_type_name (str): The name of the Kubernetes resource to check.
        namespace (str): The namespace where the resource is located.
        condition (str): The desired condition to wait for (default is "Available").
        timeout_seconds (int): The maximum number of seconds to wait (default is 300).
    
    Returns:
        bool: True if the resource reached the condition, False otherwise.
    """
    print(f"Waiting up to {timeout_seconds}s for {resource_type_name} in namespace {namespace} to be {condition}...")
    attempts: int = timeout_seconds // 30
    for i in range(attempts):
        try:
            run_kubectl_command(["wait", f"--for=condition={condition}", resource_type_name, "--timeout=30s"], namespace=namespace)
            print(f"{resource_type_name} is {condition}.")
            return True
        except SystemExit:
            if i < attempts - 1:
                print(f"Still waiting for {resource_type_name}...")
            else:
                print(f"Timeout: {resource_type_name} did not become {condition} within {timeout_seconds}s.")
                return False
        except Exception as e:
            print(f"Error waiting for {resource_type_name}: {e}")
            return False
    return False

def get_ingress_ip(ingress_name: str, namespace: str, retries: int = 24, delay_seconds: int = 15) -> str | None:
    """
    Retrieves the Ingress IP for the specified ingress resource in the given Kubernetes namespace, retrying if necessary.

    Args:
        ingress_name (str): The name of the ingress resource.
        namespace (str): The Kubernetes namespace where the ingress resource is deployed.
        retries (int, optional): Number of retry attempts (default is 24).
        delay_seconds (int, optional): Delay in seconds between retries (default is 15).

    Returns:
        str | None: The ingress IP if found, otherwise None.
    """
    print(f"Attempting to get Ingress IP for '{ingress_name}' in namespace '{namespace}' (will retry for ~{retries*delay_seconds//60} minutes)...")
    for attempt in range(retries):
        if attempt > 0:
            print(f"Attempt {attempt + 1}/{retries}: Ingress IP not available yet. Retrying in {delay_seconds}s...")
            time.sleep(delay_seconds)
        # Explicitly cast to str, as run_kubectl_command can return bool | str
        ip_output = run_kubectl_command(["get", "ingress", ingress_name, "-o", "jsonpath={.status.loadBalancer.ingress[0].ip}"], namespace=namespace, check=False, capture_output=True)
        ip: str | None = str(ip_output) if isinstance(ip_output, str) and ip_output else None

        if ip and ip != "<none>" and ip != "":
            print(f"Ingress IP found: {ip}")
            return ip
    print(f"Error: Failed to get Ingress IP for '{ingress_name}' after {retries} attempts.")
    return None

def process_yaml_template(template_path: Path, output_path: Path, replacements: dict[str, str]) -> Path:
    """
    Processes a YAML template by replacing placeholders with provided values and writes the result to an output file.

    Args:
        template_path (Path): The path to the YAML template file.
        output_path (Path): The file path where the processed YAML will be saved.
        replacements (dict): A dictionary mapping placeholder keys to their replacement values.

    Returns:
        Path: The path where the processed YAML is saved.
    """
    print(f"Processing template: {template_path} -> {output_path}")
    try:
        with open(template_path, 'r', encoding='UTF-8') as f:
            content = f.read()
        for key, value in replacements.items():
            content = content.replace(f"{{{{ {key} }}}}", str(value))
        TEMP_YAML_DIR.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='UTF-8') as f:
            f.write(content)
        return output_path
    except FileNotFoundError:
        print(f"Error: Template file not found at {template_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing template {template_path}: {e}")
        sys.exit(1)

def process_n8n_deployment_env(template_path: Path, output_path: Path, target_domain: str) -> Path:
    """
    Processes the n8n deployment YAML template by updating environment variables for n8n deployment 
    based on the target domain, and writes the updated YAML to an output file.

    Args:
        template_path (Path): The path to the n8n deployment template file.
        output_path (Path): The path where the updated deployment YAML should be saved.
        target_domain (str): The domain to set for the n8n host environment variable.

    Returns:
        Path: The path where the updated YAML is saved.
    """
    print(f"Updating n8n deployment env vars in: {template_path} -> {output_path}")
    try:
        with open(template_path, 'r', encoding='UTF-8') as f:
            deployment: dict[str, Any] = yaml.safe_load(f)
        env_vars_to_set: dict[str, str] = {"N8N_HOST": target_domain, "N8N_PROTOCOL": "https", "N8N_PORT": "5678"}

        # Perform type checks for nested structure
        if not (deployment and
                isinstance(deployment.get('spec'), dict) and
                isinstance(deployment['spec'].get('template'), dict) and
                isinstance(deployment['spec']['template'].get('spec'), dict) and
                isinstance(deployment['spec']['template']['spec'].get('containers'), list) and
                len(deployment['spec']['template']['spec']['containers']) > 0):
            print(f"Error: Invalid structure in n8n deployment template {template_path}.")
            sys.exit(1)

        container_spec: dict[str, Any] = deployment['spec']['template']['spec']['containers'][0]
        # No isinstance check for container_spec needed as it's typed dict[str, Any]

        # Ensure 'env' key exists and is a list, or initialize it
        if not isinstance(container_spec.get('env'), list):
            container_spec['env'] = [] # Initialize as an empty list if not present or not a list

        # current_env_vars is now guaranteed to be a list from container_spec['env'].
        # We assert its type for Pylance, trusting the structure or initialization.
        current_env_vars: list[dict[str, str]] = container_spec['env'] # type: ignore

        for key_to_set, value_to_set in env_vars_to_set.items():
            found = False
            for env_var in current_env_vars: # env_var is dict[str, str] due to current_env_vars type
                if env_var.get('name') == key_to_set:
                    env_var['value'] = value_to_set
                    found = True
                    break
            if not found:
                current_env_vars.append({'name': key_to_set, 'value': str(value_to_set)})

        # No need to reassign container_spec['env'] = current_env_vars if current_env_vars is a reference
        # to container_spec['env'] and modified in place.
        # However, if container_spec['env'] was initially None or not a list,
        # it was reassigned, so this is fine.

        TEMP_YAML_DIR.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='UTF-8') as f:
            yaml.dump(deployment, f, sort_keys=False, Dumper=yaml.SafeDumper)
        return output_path
    except FileNotFoundError:
        print(f"Error: Template file not found at {template_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML template {template_path}: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing n8n deployment template {template_path}: {e}")
        sys.exit(1)

def cleanup_temp_yamls() -> None:
    """
    Removes the temporary YAML directory and its contents if it exists.
    """
    if TEMP_YAML_DIR.exists():
        print(f"Cleaning up temporary YAML directory: {TEMP_YAML_DIR}")
        try:
            shutil.rmtree(TEMP_YAML_DIR)
        except Exception as e:
            print(f"Warning: Could not delete temporary directory {TEMP_YAML_DIR}: {e}")

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
    Deploys the storage components required for n8n, including persistent volume claims and storage class.

    Args:
        args: argparse.Namespace: Parsed command-line arguments.
        paths: dict[str, Path]: Dictionary containing paths to YAML files.
    """
    print("\n--- Deploying Storage ---")
    if args.force:
        delete_resource_if_force(args.force, "persistentvolumeclaim", "postgresql-pv", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "persistentvolumeclaim", "n8n-claim0", N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["storage_class"])])
    run_kubectl_command(["apply", "-f", str(paths["pg_pvc"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["n8n_pvc"])], namespace=N8N_NAMESPACE)

def deploy_postgres_component(args: argparse.Namespace, paths: dict[str, Path], pg_user_val: str, pg_password_val: str) -> None:
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
    pg_secret_replacements: dict[str, str] = {"BASE64_PG_APP_USER": b64_pg_app_user, "BASE64_PG_APP_PASSWORD": b64_pg_app_password}
    processed_pg_secret_yaml: Path = process_yaml_template(paths["pg_secret_template"], TEMP_YAML_DIR / "postgres-secret.yaml", pg_secret_replacements)

    if args.force:
        delete_resource_if_force(args.force, "secret", "postgres-secret", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "configmap", "init-data", N8N_NAMESPACE) # PG ConfigMap name
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
    processed_n8n_deployment_yaml: Path = process_n8n_deployment_env(paths["n8n_deployment_template"], TEMP_YAML_DIR / "n8n-deployment.yaml", args.domain)
    if args.force:
        delete_resource_if_force(args.force, "service", "n8n", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "deployment", "n8n", N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["n8n_service"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(processed_n8n_deployment_yaml)], namespace=N8N_NAMESPACE)
    if not wait_for_resource("deployment/n8n", N8N_NAMESPACE):
        sys.exit(1)

def deploy_ingress_component(args: argparse.Namespace, paths: dict[str, Path]) -> None:
    """
    Deploys the Ingress stack, including ManagedCertificate,
    FrontendConfig, and Ingress resources, with proper ordering
    and optional forced deletion of existing resources.

    Args:
        args: argparse.Namespace: Parsed command-line arguments.
        paths: dict[str, Path]: Dictionary containing paths to YAML files and templates.
    """
    print("\n--- Deploying Ingress Stack (ManagedCertificate, FrontendConfig, Ingress) ---")
    domain_replacements: dict[str, str] = {
        "TARGET_DOMAIN": str(args.domain) # Ensure domain is string
    }

    processed_managed_cert_yaml: Path = process_yaml_template(
        paths["managed_cert_template"],
        TEMP_YAML_DIR / "n8n-managed-certificate.yaml",
        domain_replacements,
    )
    processed_ingress_yaml: Path = process_yaml_template(
        paths["ingress_template"],
        TEMP_YAML_DIR / "n8n-ingress-tls.yaml",
        domain_replacements,
    )

    # FrontendConfig is static, no processing needed if it doesn't use {{ TARGET_DOMAIN }}
    frontend_config_path: Path = paths["frontend_config"]

    if args.force:
        # Order: Delete Ingress first,
        # then ManagedCertificate,
        # then FrontendConfig
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

    # Order: Apply FrontendConfig and ManagedCertificate before Ingress
    print("Applying FrontendConfig (n8n-frontend-config)...")
    run_kubectl_command(
        [
            "apply",
            "-f",
            str(frontend_config_path),
        ],
        namespace=N8N_NAMESPACE,
    )

    print("Applying ManagedCertificate (n8n-managed-cert)...")
    run_kubectl_command(
        [
            "apply",
            "-f",
            str(processed_managed_cert_yaml),
        ],
        namespace=N8N_NAMESPACE,
    )

    print("Applying Ingress (n8n-ingress)...")
    run_kubectl_command(
        [
            "apply",
            "-f",
            str(processed_ingress_yaml),
        ],
        namespace=N8N_NAMESPACE,
    )

def perform_dns_update_component(args: argparse.Namespace, ingress_name_for_ip: str = "n8n-ingress") -> tuple[str | None, str, types.ModuleType | None]:
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
            print(
                "No DNS providers found/loaded. "
                "Skipping DNS update."
            )
            return ingress_ip, choice_str_local, selected_provider_module

        print("\nSelect DNS Provider for Update:")
        for idx, provider_module_item in DNS_PROVIDERS.items():
            print(
                f"  {idx}. "
                f"{provider_module_item.PROVIDER_NAME}" # type: ignore
            )
        try:
            prompt: str = (
                "Enter number of DNS provider "
                "(or press Enter to skip): "
            )
            choice_str_local = input(
                prompt
            ).strip()
            if not choice_str_local:
                print(
                    "Skipping DNS update by user choice."
                )
                return ingress_ip, choice_str_local, selected_provider_module

            choice: int = int(choice_str_local)
            selected_provider_module = DNS_PROVIDERS.get(choice)
            if not selected_provider_module:
                print(
                    "Invalid choice. Skipping DNS update."
                )
                return ingress_ip, choice_str_local, selected_provider_module

            print(
                f"Proceeding with "
                f"{selected_provider_module.PROVIDER_NAME}..." # type: ignore
            )
            update_success: bool = selected_provider_module.update_dns( # type: ignore
                args.domain,
                ingress_ip
            )
            if not update_success:
                print(
                    "Warning: DNS update for "
                    f"{args.domain} via "
                    f"{selected_provider_module.PROVIDER_NAME} " # type: ignore
                    "might have failed."
                )
        except ValueError:
            print(
                "Invalid input (not a number). "
                "Skipping DNS update."
            )
    elif args.update_dns and not ingress_ip:
        print(
            f"DNS update skipped: Could not obtain "
            f"Ingress IP for {args.domain}."
        )
    return ingress_ip, choice_str_local, selected_provider_module

# --- Main Orchestration Helpers ---
def _parse_arguments_and_determine_actions() -> tuple[argparse.Namespace, dict[str, bool]]:
    """Parses command-line arguments and determines which deployment actions to run."""
    parser = argparse.ArgumentParser(description="Deploy n8n to GKE with Python.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-f", "--force", action="store_true", help="Force delete existing resources for selected components.")
    parser.add_argument("--domain", type=str, help="Target domain (e.g., n8n.example.com). Required for n8n, ingress, dns.")

    comp_group = parser.add_argument_group('Component Selection (default is --deploy-all if none specified)')
    comp_group.add_argument("--deploy-all", action="store_true", help="Deploy all components.")
    comp_group.add_argument("--deploy-namespace", action="store_true", help="Deploy/Redeploy Namespace.")
    comp_group.add_argument("--deploy-storage", action="store_true", help="Deploy/Redeploy Storage.")
    comp_group.add_argument("--deploy-postgres", action="store_true", help="Deploy/Redeploy PostgreSQL.")
    comp_group.add_argument("--deploy-n8n", action="store_true", help="Deploy/Redeploy n8n application.")
    comp_group.add_argument("--deploy-ingress", action="store_true", help="Deploy/Redeploy Ingress stack.")

    dns_group = parser.add_argument_group('DNS Update Options')
    dns_group.add_argument("--update-dns", action="store_true", help="Enable DNS update after relevant components are deployed.")
    dns_group.add_argument("--update-dns-only", action="store_true", help="Only perform DNS update (requires Ingress IP).")

    pg_group = parser.add_argument_group('PostgreSQL Options (used if deploying PostgreSQL)')
    pg_group.add_argument("--pg-user", type=str, default="n8n", help="PostgreSQL application username.")
    args: argparse.Namespace = parser.parse_args()

    actions_to_run: dict[str, bool] = {
        "namespace": args.deploy_namespace, "storage": args.deploy_storage,
        "postgres": args.deploy_postgres, "n8n": args.deploy_n8n,
        "ingress": args.deploy_ingress, "dns": args.update_dns_only
    }
    any_component_flag_set: bool = any(v for k, v in actions_to_run.items() if k != "dns")

    if args.deploy_all or not any_component_flag_set:
        for key in ["namespace", "storage", "postgres", "n8n", "ingress"]:
            actions_to_run[key] = True
        if args.update_dns: # If --update-dns was with --deploy-all or no flags
            actions_to_run["dns"] = True

    if (actions_to_run["n8n"] or actions_to_run["ingress"] or actions_to_run["dns"] or args.update_dns) and not args.domain:
        parser.error("--domain is required if deploying n8n, ingress, or performing DNS update.")
    return args, actions_to_run

def _get_and_validate_yaml_paths() -> tuple[dict[str, Path], dict[str, Path]]:
    """Defines and validates paths to static and template YAML files."""
    static_yamls: dict[str, Path] = {
        "namespace": INFRA_DIR / "namespace.yaml",
        "storage_class": INFRA_DIR / "storage" / "storage.yaml",
        "pg_pvc": INFRA_DIR / "postgres" / "postgres-claim0-persistentvolumeclaim.yaml",
        "pg_configmap": INFRA_DIR / "postgres" / "postgres-configmap.yaml",
        "pg_deployment": INFRA_DIR / "postgres" / "postgres-deployment.yaml",
        "pg_service": INFRA_DIR / "postgres" / "postgres-service.yaml",
        "n8n_pvc": INFRA_DIR / "n8n" / "n8n-claim0-persistentvolumeclaim.yaml",
        "n8n_service": INFRA_DIR / "n8n" / "n8n-service.yaml",
        "frontend_config": INFRA_DIR / "n8n" / "n8n-ingress-frontend.yaml",
    }
    template_yamls: dict[str, Path] = {
        "pg_secret_template": INFRA_DIR / "postgres" / "postgres-secret.yaml.template",
        "n8n_deployment_template": INFRA_DIR / "n8n" / "n8n-deployment.yaml.template",
        "managed_cert_template": INFRA_DIR / "n8n" / "n8n-managed-certificate.yaml.template",
        "ingress_template": INFRA_DIR / "n8n" / "n8n-ingress-tls.yaml.template",
    }
    for name, path_item in {**static_yamls, **template_yamls}.items():
        if not path_item.exists():
            print(f"Error: Required YAML file '{name}' not found at {path_item}")
            sys.exit(1)
    return static_yamls, template_yamls

def _deploy_selected_components(args: argparse.Namespace, actions_to_run: dict[str, bool], static_yamls: dict[str, Path], template_yamls: dict[str, Path]) -> str | None:
    """Orchestrates the deployment of selected components."""
    combined_yamls: dict[str, Path] = {**static_yamls, **template_yamls}
    pg_password_val: str | None = None

    if actions_to_run["namespace"]:
        deploy_namespace_component(args, static_yamls)
    if actions_to_run["storage"]:
        deploy_storage_component(args, static_yamls)
    if actions_to_run["postgres"]:
        pg_password_val = getpass.getpass(f"Enter PostgreSQL password for user '{args.pg_user}': ").strip()
        if not pg_password_val:
            print("PostgreSQL password not provided. Exiting.")
            sys.exit(1)
        deploy_postgres_component(args, combined_yamls, args.pg_user, pg_password_val)
    if actions_to_run["n8n"]:
        deploy_n8n_app_component(args, combined_yamls)
    if actions_to_run["ingress"]:
        deploy_ingress_component(args, combined_yamls)
    return pg_password_val # Though not directly used by caller main, it's part of this logical block

def _handle_dns_update_flow(args: argparse.Namespace, actions_to_run: dict[str, bool]) -> tuple[str | None, str, types.ModuleType | None]:
    """Manages the DNS update process based on arguments and deployment status."""
    ingress_ip: str | None = None
    choice_str: str = ""
    selected_provider: types.ModuleType | None = None

    # Determine if any main deployment component was flagged (excluding --deploy-all or no flags scenario)
    any_component_flag_set_for_dns_check: bool = any(
        actions_to_run[comp] for comp in ["namespace", "storage", "postgres", "n8n", "ingress"]
    )

    # Perform DNS update if --update-dns-only OR if --update-dns was set and any main component was deployed
    # This logic is a bit complex due to various flag combinations.
    should_perform_dns_update: bool = False
    if actions_to_run["dns"]: # --update-dns-only
        should_perform_dns_update = True
    elif args.update_dns:
        # Case 1: --deploy-all (or no specific deploy flags, defaulting to all) is set
        is_deploy_all_scenario = not any(
            getattr(args, f"deploy_{comp}") for comp in ["namespace", "storage", "postgres", "n8n", "ingress"]
        ) or args.deploy_all

        if is_deploy_all_scenario:
            should_perform_dns_update = True
        # Case 2: Specific deploy flags are set
        elif any_component_flag_set_for_dns_check:
            should_perform_dns_update = True


    if should_perform_dns_update:
        if not args.domain:
            print("Error: --domain is required for DNS update.")
            # Exiting or raising an error might be more robust here,
            # but following original script's pattern of printing and continuing.
        else:
            dns_update_result = perform_dns_update_component(args)
            ingress_ip, choice_str, selected_provider = dns_update_result
    return ingress_ip, choice_str, selected_provider

def _print_final_summary(args: argparse.Namespace, actions_to_run: dict[str, bool], ingress_ip: str | None, choice_str: str, selected_provider: types.ModuleType | None) -> None:
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
        dns_update_attempted = (args.update_dns or actions_to_run["dns"]) and DNS_PROVIDERS and choice_str and selected_provider
        if dns_update_attempted:
            print(f"Ensure DNS for {args.domain} has propagated to this IP.")
        else:
            # This 'else' covers cases where DNS update was intended but skipped (e.g., no provider chosen)
            # or not intended at all but an IP was found (e.g., only deploying components without --update-dns).
            if args.update_dns or actions_to_run["dns"]: # If DNS update was intended
                print(f"Please manually point DNS A record for {args.domain} to this IP if not updated by the script.")
            # If no DNS update was intended, but we have an IP, it's still useful to tell them to point DNS.
            # However, the original script only prints this if an update was *attempted* and failed or skipped.
            # To match original logic more closely, we only print manual instructions if an update was *intended*.
    elif args.update_dns or actions_to_run["dns"]: # If DNS update was intended but no IP
        print(f"Could not determine Ingress IP for {args.domain}. DNS update could not be performed.")
        print(f"Check GKE console for Load Balancer IP and manually update DNS for {args.domain}.")

    if actions_to_run["ingress"] or actions_to_run["n8n"]:
        print("Google-managed SSL certificate provisioning may take several minutes after DNS propagation and Ingress setup.")
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
        cleanup_temp_yamls()
    TEMP_YAML_DIR.mkdir(parents=True, exist_ok=True)

    ingress_ip_final: str | None = None
    choice_str_final: str = ""
    selected_provider_final: types.ModuleType | None = None

    try:
        _deploy_selected_components(args, actions_to_run, static_yamls, template_yamls)
        ingress_ip_final, choice_str_final, selected_provider_final = _handle_dns_update_flow(args, actions_to_run)
    finally:
        cleanup_temp_yamls()

    _print_final_summary(args, actions_to_run, ingress_ip_final, choice_str_final, selected_provider_final)

if __name__ == "__main__":
    main()

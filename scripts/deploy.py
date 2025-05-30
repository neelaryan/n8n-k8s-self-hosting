import subprocess
import argparse
import time
import sys
from pathlib import Path
import base64
import getpass
import shutil # For cleaning up .tmp_yamls
import yaml  # PyYAML

# --- Configuration & Imports ---
SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
INFRA_DIR = BASE_DIR / "infra"
N8N_NAMESPACE = "n8n" # Default Kubernetes namespace for n8n resources
TEMP_YAML_DIR = SCRIPT_DIR / ".tmp_yamls" # For processed YAMLs

# Dynamically import DNS providers
DNS_PROVIDERS = {}
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
def run_command(command_args, check=True, capture_output=False, text=True, shell=False, working_dir=None):
    print(f"Executing: {' '.join(command_args)}")
    try:
        process = subprocess.run(
            command_args, check=check, capture_output=capture_output, text=text, shell=shell, cwd=working_dir, timeout=360
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

def run_kubectl_command(kubectl_args, namespace=None, check=True, capture_output=False):
    cmd = ["kubectl"] + kubectl_args
    if namespace:
        cmd.extend(["-n", namespace])
    return run_command(cmd, check=check, capture_output=capture_output)

def delete_resource_if_force(force_flag, resource_type, resource_name, namespace=None, check_kubectl_errors=False):
    if force_flag:
        print(f"Force mode: Deleting {resource_type} {resource_name}" + (f" in namespace {namespace}" if namespace else ""))
        run_kubectl_command(["delete", resource_type, resource_name, "--ignore-not-found=true"], namespace=namespace, check=check_kubectl_errors)

def delete_namespace_if_force(force_flag, namespace_to_delete):
    if force_flag:
        print(f"Force mode: Deleting namespace {namespace_to_delete}...")
        run_kubectl_command(["delete", "namespace", namespace_to_delete, "--ignore-not-found=true"], check=False)
        print(f"Waiting for namespace {namespace_to_delete} to be terminated (up to ~60s)...")
        for i in range(12):
            time.sleep(5)
            ns_exists_output = run_kubectl_command(["get", "namespace", namespace_to_delete, "--ignore-not-found", "-o", "name"], check=False, capture_output=True)
            if not ns_exists_output: print(f"Namespace {namespace_to_delete} terminated."); return
            if i == 5 : print(f"Still waiting for namespace {namespace_to_delete} to terminate...")
        print(f"Warning: Namespace {namespace_to_delete} might still be terminating after 60s.")

def wait_for_resource(resource_type_name, namespace, condition="Available", timeout_seconds=300):
    print(f"Waiting up to {timeout_seconds}s for {resource_type_name} in namespace {namespace} to be {condition}...")
    attempts = timeout_seconds // 30 
    for i in range(attempts):
        try:
            run_kubectl_command(["wait", f"--for=condition={condition}", resource_type_name, "--timeout=30s"], namespace=namespace)
            print(f"{resource_type_name} is {condition}."); return True
        except SystemExit: 
            if i < attempts - 1: print(f"Still waiting for {resource_type_name}...")
            else: print(f"Timeout: {resource_type_name} did not become {condition} within {timeout_seconds}s."); return False
        except Exception as e: print(f"Error waiting for {resource_type_name}: {e}"); return False
    return False

def get_ingress_ip(ingress_name, namespace, retries=24, delay_seconds=15):
    print(f"Attempting to get Ingress IP for '{ingress_name}' in namespace '{namespace}' (will retry for ~{retries*delay_seconds//60} minutes)...")
    for attempt in range(retries):
        if attempt > 0: 
            print(f"Attempt {attempt + 1}/{retries}: Ingress IP not available yet. Retrying in {delay_seconds}s...")
            time.sleep(delay_seconds)
        ip = run_kubectl_command(["get", "ingress", ingress_name, "-o", "jsonpath={.status.loadBalancer.ingress[0].ip}"], namespace=namespace, check=False, capture_output=True)
        if ip and ip != "<none>" and ip != "": print(f"Ingress IP found: {ip}"); return ip
    print(f"Error: Failed to get Ingress IP for '{ingress_name}' after {retries} attempts."); return None

def process_yaml_template(template_path, output_path, replacements):
    print(f"Processing template: {template_path} -> {output_path}")
    try:
        with open(template_path, 'r', encoding='UTF-8') as f: content = f.read()
        for key, value in replacements.items(): content = content.replace(f"{{{{ {key} }}}}", str(value))
        TEMP_YAML_DIR.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='UTF-8') as f: f.write(content)
        return output_path
    except FileNotFoundError: print(f"Error: Template file not found at {template_path}"); sys.exit(1)
    except Exception as e: print(f"Error processing template {template_path}: {e}"); sys.exit(1)

def process_n8n_deployment_env(template_path, output_path, target_domain):
    print(f"Updating n8n deployment env vars in: {template_path} -> {output_path}")
    try:
        with open(template_path, 'r', encoding='UTF-8') as f: deployment = yaml.safe_load(f)
        env_vars_to_set = {"N8N_HOST": target_domain, "N8N_PROTOCOL": "https", "N8N_PORT": "5678"}
        if not (deployment and 'spec' in deployment and 'template' in deployment['spec'] and \
                'spec' in deployment['spec']['template'] and 'containers' in deployment['spec']['template']['spec'] and \
                len(deployment['spec']['template']['spec']['containers']) > 0):
            print(f"Error: Invalid structure in n8n deployment template {template_path}."); sys.exit(1)
        container_spec = deployment['spec']['template']['spec']['containers'][0]
        if 'env' not in container_spec or container_spec['env'] is None: container_spec['env'] = []
        current_env_vars = container_spec['env']
        for key_to_set, value_to_set in env_vars_to_set.items():
            found = False
            for env_var in current_env_vars:
                if env_var['name'] == key_to_set: env_var['value'] = value_to_set; found = True; break
            if not found: current_env_vars.append({'name': key_to_set, 'value': value_to_set})
        container_spec['env'] = current_env_vars
        TEMP_YAML_DIR.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='UTF-8') as f: yaml.dump(deployment, f, sort_keys=False, Dumper=yaml.SafeDumper)
        return output_path
    except FileNotFoundError: print(f"Error: Template file not found at {template_path}"); sys.exit(1)
    except yaml.YAMLError as e: print(f"Error parsing YAML template {template_path}: {e}"); sys.exit(1)
    except Exception as e: print(f"Error processing n8n deployment template {template_path}: {e}"); sys.exit(1)

def cleanup_temp_yamls():
    if TEMP_YAML_DIR.exists():
        print(f"Cleaning up temporary YAML directory: {TEMP_YAML_DIR}")
        try: shutil.rmtree(TEMP_YAML_DIR)
        except Exception as e: print(f"Warning: Could not delete temporary directory {TEMP_YAML_DIR}: {e}")

# --- Component Deployment Functions ---
def deploy_namespace_component(args, paths):
    print("\n--- Deploying Namespace ---")
    if args.force: delete_namespace_if_force(args.force, N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["namespace"])])

def deploy_storage_component(args, paths):
    print("\n--- Deploying Storage ---")
    if args.force:
        delete_resource_if_force(args.force, "persistentvolumeclaim", "postgresql-pv", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "persistentvolumeclaim", "n8n-claim0", N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["storage_class"])])
    run_kubectl_command(["apply", "-f", str(paths["pg_pvc"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["n8n_pvc"])], namespace=N8N_NAMESPACE)

def deploy_postgres_component(args, paths, pg_user_val, pg_password_val):
    print("\n--- Deploying PostgreSQL ---")
    b64_pg_app_user = base64.b64encode(pg_user_val.encode('utf-8')).decode('utf-8')
    b64_pg_app_password = base64.b64encode(pg_password_val.encode('utf-8')).decode('utf-8')
    pg_secret_replacements = {"BASE64_PG_APP_USER": b64_pg_app_user, "BASE64_PG_APP_PASSWORD": b64_pg_app_password}
    processed_pg_secret_yaml = process_yaml_template(paths["pg_secret_template"], TEMP_YAML_DIR / "postgres-secret.yaml", pg_secret_replacements)

    if args.force:
        delete_resource_if_force(args.force, "secret", "postgres-secret", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "configmap", "init-data", N8N_NAMESPACE) # PG ConfigMap name
        delete_resource_if_force(args.force, "deployment", "postgres", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "service", "postgres-service", N8N_NAMESPACE)
        
    run_kubectl_command(["apply", "-f", str(processed_pg_secret_yaml)], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["pg_configmap"])], namespace=N8N_NAMESPACE) 
    run_kubectl_command(["apply", "-f", str(paths["pg_deployment"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["pg_service"])], namespace=N8N_NAMESPACE)
    if not wait_for_resource("deployment/postgres", N8N_NAMESPACE): sys.exit(1)

def deploy_n8n_app_component(args, paths):
    print("\n--- Deploying n8n Application ---")
    processed_n8n_deployment_yaml = process_n8n_deployment_env(paths["n8n_deployment_template"], TEMP_YAML_DIR / "n8n-deployment.yaml", args.domain)
    if args.force:
        delete_resource_if_force(args.force, "service", "n8n", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "deployment", "n8n", N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(paths["n8n_service"])], namespace=N8N_NAMESPACE)
    run_kubectl_command(["apply", "-f", str(processed_n8n_deployment_yaml)], namespace=N8N_NAMESPACE)
    if not wait_for_resource("deployment/n8n", N8N_NAMESPACE):
        sys.exit(1)

def deploy_ingress_component(args, paths): # paths will now include frontend_config
    print("\n--- Deploying Ingress Stack (ManagedCertificate, FrontendConfig, Ingress) ---")
    domain_replacements = {"TARGET_DOMAIN": args.domain}

    processed_managed_cert_yaml = process_yaml_template(
        paths["managed_cert_template"],
        TEMP_YAML_DIR / "n8n-managed-certificate.yaml",
        domain_replacements
    )
    processed_ingress_yaml = process_yaml_template(
        paths["ingress_template"], # This is your updated template
        TEMP_YAML_DIR / "n8n-ingress-tls.yaml",
        domain_replacements
    )

    # FrontendConfig is static, no processing needed if it doesn't use {{ TARGET_DOMAIN }}
    frontend_config_path = paths["frontend_config"]

    if args.force:
         # Order: Delete Ingress first, then ManagedCertificate, then FrontendConfig
        delete_resource_if_force(args.force, "ingress", "n8n-ingress", N8N_NAMESPACE)
        delete_resource_if_force(args.force, "managedcertificate", "n8n-managed-cert", N8N_NAMESPACE, check_kubectl_errors=False)
        delete_resource_if_force(args.force, "frontendconfig", "n8n-frontend-config", N8N_NAMESPACE, check_kubectl_errors=False)

    # Order: Apply FrontendConfig and ManagedCertificate before Ingress
    print("Applying FrontendConfig (n8n-frontend-config)...")
    run_kubectl_command(["apply", "-f", str(frontend_config_path)], namespace=N8N_NAMESPACE)

    print("Applying ManagedCertificate (n8n-managed-cert)...")
    run_kubectl_command(["apply", "-f", str(processed_managed_cert_yaml)], namespace=N8N_NAMESPACE)

    print("Applying Ingress (n8n-ingress)...")
    run_kubectl_command(["apply", "-f", str(processed_ingress_yaml)], namespace=N8N_NAMESPACE)

def perform_dns_update_component(args, ingress_name_for_ip="n8n-ingress"):
    print("\n--- Ingress IP & DNS Update ---")
    ingress_ip = get_ingress_ip(ingress_name_for_ip, N8N_NAMESPACE)
    selected_provider_module = None # Renamed to avoid conflict with main scope
    choice_str_local = "" # Renamed for local scope

    if args.update_dns and ingress_ip: # This condition is now part of the caller's logic
        if not DNS_PROVIDERS:
            print("No DNS providers found/loaded. Skipping DNS update.")
        else:
            print("\nSelect DNS Provider for Update:")
            for idx, provider_module_item in DNS_PROVIDERS.items():
                print(f"  {idx}. {provider_module_item.PROVIDER_NAME}")
            try:
                choice_str_local = input("Enter number of DNS provider (or press Enter to skip): ").strip()
                if not choice_str_local:
                    print("Skipping DNS update by user choice.")
                else:
                    choice = int(choice_str_local)
                    selected_provider_module = DNS_PROVIDERS.get(choice)
                    if selected_provider_module:
                        print(f"Proceeding with {selected_provider_module.PROVIDER_NAME}...")
                        if not selected_provider_module.update_dns(args.domain, ingress_ip):
                            print(f"Warning: DNS update for {args.domain} via {selected_provider_module.PROVIDER_NAME} might have failed.")
                    else: print("Invalid choice. Skipping DNS update.")
            except ValueError:
                print("Invalid input (not a number). Skipping DNS update.")
    elif args.update_dns and not ingress_ip:
        print(f"DNS update skipped: Could not obtain Ingress IP for {args.domain}.")
    return ingress_ip, choice_str_local, selected_provider_module

# --- Main Orchestration ---
def main():
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
    args = parser.parse_args()

    actions_to_run = {
        "namespace": args.deploy_namespace, "storage": args.deploy_storage,
        "postgres": args.deploy_postgres, "n8n": args.deploy_n8n,
        "ingress": args.deploy_ingress, "dns": args.update_dns_only
    }
    any_component_flag_set = any(v for k, v in actions_to_run.items() if k != "dns") # Check if any --deploy-* is true

    if args.deploy_all or not any_component_flag_set: # If --deploy-all or no --deploy-* flags, do all
        for key in ["namespace", "storage", "postgres", "n8n", "ingress"]:
            actions_to_run[key] = True
        if args.update_dns:
            actions_to_run["dns"] = True # If --update-dns was with --deploy-all or no flags

    if (actions_to_run["n8n"] or actions_to_run["ingress"] or actions_to_run["dns"] or args.update_dns) and not args.domain:
        parser.error("--domain is required if deploying n8n, ingress, or performing DNS update.")

    static_yamls = {
        "namespace": INFRA_DIR / "namespace.yaml",
        "storage_class": INFRA_DIR / "storage" / "storage.yaml",
        "pg_pvc": INFRA_DIR / "postgres" / "postgres-claim0-persistentvolumeclaim.yaml",
        "pg_configmap": INFRA_DIR / "postgres" / "postgres-configmap.yaml",
        "pg_deployment": INFRA_DIR / "postgres" / "postgres-deployment.yaml",
        "pg_service": INFRA_DIR / "postgres" / "postgres-service.yaml",
        "n8n_pvc": INFRA_DIR / "n8n" / "n8n-claim0-persistentvolumeclaim.yaml",
        "n8n_service": INFRA_DIR / "n8n" / "n8n-service.yaml",
        "frontend_config": INFRA_DIR / "n8n" / "n8n-ingress-frontend.yaml", # Added FrontendConfig
    }
    template_yamls = {
        "pg_secret_template": INFRA_DIR / "postgres" / "postgres-secret.yaml.template",
        "n8n_deployment_template": INFRA_DIR / "n8n" / "n8n-deployment.yaml.template",
        "managed_cert_template": INFRA_DIR / "n8n" / "n8n-managed-certificate.yaml.template",
        "ingress_template": INFRA_DIR / "n8n" / "n8n-ingress-tls.yaml.template",
    }
    for name, path in {**static_yamls, **template_yamls}.items():
        if not path.exists():
            print(f"Error: Required YAML file '{name}' not found at {path}")
            sys.exit(1)

    print(f"Starting n8n GKE deployment for domain: {args.domain if args.domain else 'N/A'}...")
    if args.force:
        print("Force mode enabled for selected components.")

    if TEMP_YAML_DIR.exists() and args.force:
        cleanup_temp_yamls()
    TEMP_YAML_DIR.mkdir(parents=True, exist_ok=True)

    pg_password_val = None # Initialize
    ingress_ip_final = None
    choice_str_final = ""
    selected_provider_final = None

    try:
        if actions_to_run["namespace"]:
            deploy_namespace_component(args, static_yamls)
        if actions_to_run["storage"]:
            deploy_storage_component(args, static_yamls)
        if actions_to_run["postgres"]:
            pg_password_val = getpass.getpass(f"Enter PostgreSQL password for user '{args.pg_user}': ").strip()
            if not pg_password_val:
                print("PostgreSQL password not provided. Exiting.")
                sys.exit(1)
            deploy_postgres_component(args, {**static_yamls, **template_yamls}, args.pg_user, pg_password_val)
        if actions_to_run["n8n"]:
            deploy_n8n_app_component(args, {**static_yamls, **template_yamls})
        if actions_to_run["ingress"]:
            deploy_ingress_component(args, {**static_yamls, **template_yamls}) # Pass combined dict

        # Perform DNS update if --update-dns-only OR if --update-dns was set and any main component was deployed
        if actions_to_run["dns"] or (args.update_dns and any_component_flag_set and not args.deploy_all and not actions_to_run["dns"]):
            if not args.domain:
                print("Error: --domain is required for DNS update.")
            else: ingress_ip_final, choice_str_final, selected_provider_final = perform_dns_update_component(args)
        elif args.update_dns and (args.deploy_all or not any_component_flag_set): # Handles --deploy-all --update-dns or just --update-dns
            if not args.domain:
                print("Error: --domain is required for DNS update.")
            else: ingress_ip_final, choice_str_final, selected_provider_final = perform_dns_update_component(args)


    finally: cleanup_temp_yamls()

    print("\n---------------------------------------------------------------------")
    print("Deployment script finished.")
    if args.domain:
        print(f"n8n should eventually be accessible at: https://{args.domain}")
    if ingress_ip_final:
        print(f"The Ingress IP is: {ingress_ip_final}.")
        dns_update_attempted = (actions_to_run["dns"] or args.update_dns) and DNS_PROVIDERS and choice_str_final and selected_provider_final
        if dns_update_attempted:
            print(f"Ensure DNS for {args.domain} has propagated to this IP.")
        else: print(f"Please manually point DNS A record for {args.domain} to this IP if not updated.")
    elif args.update_dns or actions_to_run["dns"] : # If DNS update was intended but no IP
        print(f"Could not determine Ingress IP for {args.domain}. DNS update could not be performed.")
        print(f"Check GKE console for Load Balancer IP and manually update DNS for {args.domain}.")
    if actions_to_run["ingress"] or actions_to_run["n8n"] :
        print("Google-managed SSL certificate provisioning may take several minutes after DNS propagation and Ingress setup.")
    print("---------------------------------------------------------------------")

if __name__ == "__main__":
    main()

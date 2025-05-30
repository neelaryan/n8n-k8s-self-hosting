"""
Helper functions for the n8n Kubernetes deployment script.
"""
import subprocess
import time
import sys
from pathlib import Path
import shutil
from typing import Any
import yaml  # For process_n8n_deployment_env

# --- Helper Functions ---
def run_command(
    command_args: list[str],
    check: bool = True,
    capture_output: bool = False,
    text: bool = True,
    exec_config: dict[str, Any] | None = None
) -> bool | str:
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
    use_shell: bool = bool(cfg.get('shell', False))  # Ensure bool
    use_working_dir: str | Path | None = cfg.get('working_dir')  # type: ignore
    cmd_timeout: int = int(cfg.get('timeout', 360))  # Ensure int

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

def run_kubectl_command(
    kubectl_args: list[str],
    namespace: str | None = None,
    check: bool = True,
    capture_output: bool = False
) -> bool | str:
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

def delete_resource_if_force(
    force_flag: bool,
    resource_type: str,
    resource_name: str,
    namespace: str | None = None,
    check_kubectl_errors: bool = False
) -> None:
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
        delete_msg = f"Force mode: Deleting {resource_type} {resource_name}"
        if namespace:
            delete_msg += f" in namespace {namespace}"
        print(delete_msg)
        run_kubectl_command(
            ["delete", resource_type, resource_name, "--ignore-not-found=true"],
            namespace=namespace,
            check=check_kubectl_errors
        )

def delete_namespace_if_force(force_flag: bool, namespace_to_delete: str) -> None:
    """
    Deletes the specified namespace if the force flag is enabled.
    """
    if force_flag:
        print(f"Force mode: Deleting namespace {namespace_to_delete}...")
        run_kubectl_command(
            ["delete", "namespace", namespace_to_delete, "--ignore-not-found=true"],
            check=False
        )
        print(f"Waiting for namespace {namespace_to_delete} to be terminated (up to ~60s)...")
        for i in range(12):
            time.sleep(5)
            ns_exists_output = run_kubectl_command(
                ["get", "namespace", namespace_to_delete, "--ignore-not-found", "-o", "name"],
                check=False,
                capture_output=True
            )
            if not ns_exists_output:
                print(f"Namespace {namespace_to_delete} terminated.")
                return
            if i == 5 :
                print(f"Still waiting for namespace {namespace_to_delete} to terminate...")
        print(f"Warning: Namespace {namespace_to_delete} might still be terminating after 60s.")

def wait_for_resource(
    resource_type_name: str,
    namespace: str,
    condition: str = "Available",
    timeout_seconds: int = 300
) -> bool:
    """
    Waits until the specified Kubernetes resource
    reaches the desired condition within a timeout period.
    
    Args:
        resource_type_name (str): The name of the Kubernetes resource to check.
        namespace (str): The namespace where the resource is located.
        condition (str): The desired condition to wait for (default is "Available").
        timeout_seconds (int): The maximum number of seconds to wait (default is 300).
    
    Returns:
        bool: True if the resource reached the condition, False otherwise.
    """
    wait_msg = (
        f"Waiting up to {timeout_seconds}s for {resource_type_name} "
        f"in namespace {namespace} to be {condition}..."
    )
    print(wait_msg)
    attempts: int = timeout_seconds // 30
    for i in range(attempts):
        try:
            run_kubectl_command(
                ["wait", f"--for=condition={condition}", resource_type_name, "--timeout=30s"],
                namespace=namespace
            )
            print(f"{resource_type_name} is {condition}.")
            return True
        except SystemExit:
            if i < attempts - 1:
                print(f"Still waiting for {resource_type_name}...")
            else:
                timeout_msg = (
                    f"Timeout: {resource_type_name} did not become {condition} "
                    f"within {timeout_seconds}s."
                )
                print(timeout_msg)
                raise
        # If an unexpected error other than SystemExit occurs
        # (which run_kubectl_command should prevent),
        # let it propagate for clearer debugging.
    return False

def get_ingress_ip(
    ingress_name: str,
    namespace: str,
    retries: int = 24,
    delay_seconds: int = 15
) -> str | None:
    """
    Retrieves the Ingress IP for the specified ingress resource
    in the given Kubernetes namespace, retrying if necessary.

    Args:
        ingress_name (str): The name of the ingress resource.
        namespace (str): The Kubernetes namespace where the ingress resource is deployed.
        retries (int, optional): Number of retry attempts (default is 24).
        delay_seconds (int, optional): Delay in seconds between retries (default is 15).

    Returns:
        str | None: The ingress IP if found, otherwise None.
    """
    retry_minutes = retries * delay_seconds // 60
    print(
        f"Attempting to get Ingress IP for '{ingress_name}' in namespace '{namespace}' "
        f"(will retry for ~{retry_minutes} minutes)..."
    )
    for attempt in range(retries):
        if attempt > 0:
            print(
                f"Attempt {attempt + 1}/{retries}: Ingress IP not available yet. "
                f"Retrying in {delay_seconds}s..."
            )
            time.sleep(delay_seconds)
        # Explicitly cast to str, as run_kubectl_command can return bool | str
        ip_output = run_kubectl_command(
            ["get", "ingress", ingress_name, "-o", "jsonpath={.status.loadBalancer.ingress[0].ip}"],
            namespace=namespace,
            check=False,
            capture_output=True
        )
        ip: str | None = str(ip_output) if isinstance(ip_output, str) and ip_output else None

        if ip and ip != "<none>" and ip != "":
            print(f"Ingress IP found: {ip}")
            return ip
    print(f"Error: Failed to get Ingress IP for '{ingress_name}' after {retries} attempts.")
    return None

def process_yaml_template(
    template_path: Path,
    output_path: Path,
    replacements: dict[str, str],
    temp_yaml_dir: Path
) -> Path:
    """
    Processes a YAML template by replacing placeholders with provided values.

    Args:
        template_path: The path to the YAML template file.
        output_path: The file path where the processed YAML will be saved.
        replacements: A dictionary mapping placeholder keys to replacement values.
        temp_yaml_dir: The directory for temporary YAML files.

    Returns:
        Path: The path where the processed YAML is saved.
    """
    print(f"Processing template: {template_path} -> {output_path}")
    try:
        with open(template_path, 'r', encoding='UTF-8') as f:
            content = f.read()

        # Replace all placeholders with their values
        for key, value in replacements.items():
            content = content.replace(f"{{{{ {key} }}}}", str(value))

        # Ensure output directory exists
        temp_yaml_dir.mkdir(parents=True, exist_ok=True)

        # Write processed content
        with open(output_path, 'w', encoding='UTF-8') as f:
            f.write(content)

        return output_path

    except FileNotFoundError:
        print(f"Error: Template file not found at {template_path}")
        sys.exit(1)
    except PermissionError as e:
        msg = f"Error processing template {template_path} (PermissionError): {e}"
        print(msg)
        sys.exit(1)
    except UnicodeError as e:
        msg = f"Error processing template {template_path} (UnicodeError): {e}"
        print(msg)
        sys.exit(1)
    except OSError as e:
        msg = f"Error processing template {template_path} (OSError): {e}"
        print(msg)
        sys.exit(1)

# --- n8n Deployment YAML Processing Helpers ---

def _load_and_validate_n8n_template(template_path: Path) -> dict[str, Any]:
    """Loads and validates the structure of the n8n deployment YAML template."""
    try:
        with open(template_path, 'r', encoding='UTF-8') as f:
            deployment: dict[str, Any] = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Template file not found at {template_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML template {template_path}: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Error reading template {template_path} (PermissionError): {e}")
        sys.exit(1)
    except UnicodeError as e:
        print(f"Error reading template {template_path} (UnicodeError): {e}")
        sys.exit(1)
    except OSError as e:
        print(f"Error reading template {template_path} (OSError): {e}")
        sys.exit(1)


    valid_structure = (
        deployment and
        isinstance(deployment.get('spec'), dict) and
        isinstance(deployment['spec'].get('template'), dict) and
        isinstance(deployment['spec']['template'].get('spec'), dict) and
        isinstance(
            deployment['spec']['template']['spec'].get('containers'),
            list
        ) and
        len(deployment['spec']['template']['spec']['containers']) > 0
    )

    if not valid_structure:
        msg = f"Error: Invalid structure in n8n deployment template {template_path}"
        print(msg)
        sys.exit(1)
    return deployment

def _update_n8n_env_vars(
    deployment: dict[str, Any],
    target_domain: str
) -> None:
    """Updates the environment variables in the n8n container spec."""
    env_vars_to_set = {
        "N8N_HOST": target_domain,
        "N8N_PROTOCOL": "https",
        "N8N_PORT": "5678"
    }
    try:
        container_spec = deployment['spec']['template']['spec']['containers'][0]

        if not isinstance(container_spec.get('env'), list):
            container_spec['env'] = []

        current_env_vars: list[dict[str, str]] = container_spec['env']

        for key_to_set, value_to_set in env_vars_to_set.items():
            found = False
            for env_var in current_env_vars:
                if env_var.get('name') == key_to_set:
                    env_var['value'] = value_to_set
                    found = True
                    break
            if not found:
                current_env_vars.append({
                    'name': key_to_set,
                    'value': str(value_to_set)
                })
    except (KeyError, TypeError, IndexError) as e:
        # IndexError for cases where 'containers' might be empty after initial check
        # (though unlikely given the validation)
        msg = f"Error processing n8n deployment data structure (DataError): {e}"
        print(msg)
        sys.exit(1)


def _write_processed_n8n_yaml(
    deployment: dict[str, Any],
    output_path: Path,
    temp_yaml_dir: Path
) -> None:
    """Writes the processed n8n deployment YAML to the output file."""
    try:
        temp_yaml_dir.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='UTF-8') as f:
            yaml.dump(
                deployment,
                f,
                sort_keys=False,
                Dumper=yaml.SafeDumper
            )
    except PermissionError as e:
        msg = f"Error writing processed YAML to {output_path} (PermissionError): {e}"
        print(msg)
        sys.exit(1)
    except UnicodeError as e:
        msg = f"Error writing processed YAML to {output_path} (UnicodeError): {e}"
        print(msg)
        sys.exit(1)
    except OSError as e:
        msg = f"Error writing processed YAML to {output_path} (OSError): {e}"
        print(msg)
        sys.exit(1)
    except yaml.YAMLError as e: # Should not happen with dump, but good practice
        print(f"Error during YAML serialization for {output_path}: {e}")
        sys.exit(1)

def process_n8n_deployment_env(
    template_path: Path,
    output_path: Path,
    target_domain: str,
    temp_yaml_dir: Path
) -> Path:
    """
    Processes the n8n deployment YAML template.

    Updates environment variables for n8n deployment based on the target domain
    and writes the updated YAML to an output file.

    Args:
        template_path: The path to the n8n deployment template file.
        output_path: The path for the updated deployment YAML.
        target_domain: The domain for the n8n host environment variable.
        temp_yaml_dir: The directory for temporary YAML files.

    Returns:
        Path: The path where the updated YAML is saved.
    """
    print(f"Updating n8n deployment env vars in: {template_path} -> {output_path}")

    # Step 1: Load and validate the template
    deployment = _load_and_validate_n8n_template(template_path)

    # Step 2: Update environment variables
    _update_n8n_env_vars(deployment, target_domain)

    # Step 3: Write the processed YAML
    _write_processed_n8n_yaml(deployment, output_path, temp_yaml_dir)

    return output_path

def cleanup_temp_yamls(temp_yaml_dir: Path) -> None:
    """
    Removes the temporary YAML directory and its contents if it exists.

    Args:
        temp_yaml_dir: The Path object representing the temporary YAML directory.
    """
    if temp_yaml_dir.exists():
        print(f"Cleaning up temporary YAML directory: {temp_yaml_dir}")
        try:
            shutil.rmtree(temp_yaml_dir)
        except shutil.Error as e:  # Higher-level shutil errors
            print(
                f"Warning: Could not delete temporary directory "
                f"{temp_yaml_dir} (shutil error): {e}"
            )
        except FileNotFoundError:
            # This is common if directory was never created or already cleaned up
            print(
                f"Info: Temporary directory {temp_yaml_dir} "
                "not found for cleanup (already gone or not created)."
            )
        except PermissionError as e:
            print(
                f"Warning: Could not delete temporary directory "
                f"{temp_yaml_dir} due to a permission error: {e}"
            )
        except NotADirectoryError as e:
            print(
                f"Warning: Expected {temp_yaml_dir} to be a directory "
                f"for cleanup, but it was not: {e}"
            )
        except OSError as e:  # Catch other OS-level errors during rmtree
            print(
                f"Warning: Could not delete temporary directory "
                f"{temp_yaml_dir} due to an OS error: {e}"
            )

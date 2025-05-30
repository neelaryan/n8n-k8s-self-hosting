# n8n Self-Hosting on Kubernetes (Community Edition)

This project provides an enhanced and automated solution for deploying the **n8n Community Edition** on Kubernetes. It can be found at [https://github.com/neelaryan/n8n-k8s-self-hosting](https://github.com/neelaryan/n8n-k8s-self-hosting).

This solution builds upon the official Kubernetes manifests provided by the n8n team at [n8n-io/n8n-kubernetes-hosting](https://github.com/n8n-io/n8n-kubernetes-hosting). Our goal is to simplify the self-hosting process, initially with optimizations for **Google Kubernetes Engine (GKE)**, and to provide a user-friendly Python-based deployment script (`scripts/deploy.py`). This script orchestrates the creation of all necessary Kubernetes resources.

**Current GKE-Specific Optimizations:**
*   **Ingress:** Utilizes GKE Ingress, which provisions Google Cloud Load Balancers.
*   **SSL Certificates:** Integrates with Google Managed Certificates for automated SSL provisioning and renewal.
*   **HTTP-to-HTTPS Redirection:** Uses GKE's `FrontendConfig` resource.
*   **Persistent Storage:** Defaults to GCE Persistent Disks via the provided StorageClass.

We are actively working to expand the scope of this project to support other Kubernetes platforms and deployment options for the n8n Community Edition in future releases. Contributions and feedback for broader compatibility are welcome!

## Features

*   **Automated Deployment:** Python script (`scripts/deploy.py`) for deploying and managing the n8n Community Edition stack on GKE.
*   **Based on Official Manifests:** Uses Kubernetes YAMLs adapted from [n8n-io/n8n-kubernetes-hosting](https://github.com/n8n-io/n8n-kubernetes-hosting) as a foundation.
*   **PostgreSQL Database:** Deploys a PostgreSQL instance as the backend database for n8n.
*   **Google Managed SSL:** Leverages GKE's Managed Certificates for automated SSL.
*   **HTTP to HTTPS Redirection:** Includes `FrontendConfig` for GKE.
*   **Dynamic DNS Support:** Optional integration with DNS providers (e.g., FreeDNS).
*   **Selective Redeployment:** Allows targeting specific components for redeployment.
*   **Configurable:** Key parameters like domain name and PostgreSQL user can be configured at runtime.

## Project Structure

```
n8n-k8s-self-hosting/  # Project Root (https://github.com/neelaryan/n8n-k8s-self-hosting)
├── infra/                  
│   ├── namespace.yaml
│   ├── storage/
│   │   └── storage.yaml
│   ├── postgres/           
│   │   ├── postgres-claim0-persistentvolumeclaim.yaml
│   │   ├── postgres-configmap.yaml  (metadata.name: init-data)
│   │   ├── postgres-deployment.yaml
│   │   ├── postgres-secret.yaml.template
│   │   └── postgres-service.yaml
│   └── n8n/                
│       ├── n8n-claim0-persistentvolumeclaim.yaml
│       ├── n8n-deployment.yaml.template
│       ├── n8n-service.yaml
│       ├── n8n-managed-certificate.yaml.template
│       ├── n8n-ingress-tls.yaml.template
│       └── n8n-ingress-frontend.yaml
├── scripts/
│   ├── deploy.py             
│   ├── requirements.txt      
│   ├── scale-cluster.ps1     
│   └── dns_providers/        
│       ├── __init__.py
│       └── freedns_updater.py
├── .gitignore
├── LICENSE                 # MIT License for this project's scripts & configurations
└── README.md
```

## Prerequisites

*   **Google Cloud Project:** A GCP project with billing enabled.
*   **GKE Cluster:** An active GKE cluster. The `scripts/scale-cluster.ps1` script can be used to create/scale a basic cluster, or you can use your existing one.
*   **`gcloud` CLI:** Authenticated and configured to connect to your GCP project and GKE cluster.
*   **`kubectl` CLI:** Configured to communicate with your GKE cluster.
*   **Python 3:** With `pip` for installing dependencies. A virtual environment is highly recommended.
*   **Custom Domain:** You need a domain name that you can manage DNS records for.
*   **(Optional) FreeDNS Account:** If using the FreeDNS updater, you'll need an account and your update token/credentials.
*   Familiarity with Kubernetes concepts is beneficial.

## Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/neelaryan/n8n-k8s-self-hosting.git
    cd n8n-k8s-self-hosting 
    ```

2.  **Vendor/Verify Base Kubernetes Manifests:**
    *   This project uses base YAML configurations for PostgreSQL and n8n core components adapted from the official [n8n-io/n8n-kubernetes-hosting](https://github.com/n8n-io/n8n-kubernetes-hosting) repository (which is also MIT licensed).
    *   Ensure the static YAML files in `infra/postgres/` and `infra/n8n/` (those not ending in `.template`) are present and reflect the desired base configuration. If you need to update them, refer to the official n8n repository.
    *   **Key files to verify (vendored by you):**
        *   `infra/postgres/postgres-configmap.yaml` (ensure `metadata.name: init-data`).
        *   `infra/postgres/postgres-deployment.yaml` (ensure it correctly references `init-data` ConfigMap and `postgres-secret` with keys `POSTGRES_NON_ROOT_USER`/`PASSWORD`).
        *   Other static YAMLs like `namespace.yaml`, `storage.yaml`, PVCs, and services.

3.  **Set up Python Virtual Environment (Recommended):**
    ```bash
    python -m venv .venv 
    # On Windows cmd.exe:
    .venv\Scripts\activate.bat
    # On Linux/macOS bash/zsh:
    # source .venv/bin/activate
    ```

4.  **Install Python Dependencies:**
    ```bash
    pip install -r scripts/requirements.txt
    ```

5.  **Prepare `.gitignore`:**
    Ensure `.venv/`, `scripts/.tmp_yamls/`, `__pycache__/`, `*.pyc` are included.

## Deployment

The main deployment script is `scripts/deploy.py`.

**Full Deployment (Recommended for first time):**

```bash
# Ensure your virtual environment is active
# Example: .venv\Scripts\activate.bat

python scripts/deploy.py --domain your.n8n-domain.com --pg-user mypguser --update-dns --force
```

You will be prompted for:
*   The password for the PostgreSQL user (`mypguser` in the example).
*   If `--update-dns` is used and a provider is selected, credentials for that DNS provider.

**Command-Line Arguments for `scripts/deploy.py`:**

*   `--domain YOUR_DOMAIN` (Required for n8n/ingress/dns): Your custom domain for n8n (e.g., `n8n.example.com`).
*   `-f, --force`: Force delete and recreate components if they already exist. Useful for ensuring a clean state.
*   `--pg-user USERNAME`: Username for the PostgreSQL n8n application user (default: `n8n`). Password will be prompted.
*   `--update-dns`: Enable automatic DNS update after Ingress IP is obtained.
*   **Selective Deployment Flags:**
    *   `--deploy-all`: Deploy all components (default if no other `--deploy-*` flag is set).
    *   `--deploy-namespace`: Deploy/Redeploy only the Kubernetes Namespace.
    *   `--deploy-storage`: Deploy/Redeploy only Storage components (StorageClass, PVCs).
    *   `--deploy-postgres`: Deploy/Redeploy only PostgreSQL (ConfigMap, Secret, Deployment, Service).
    *   `--deploy-n8n`: Deploy/Redeploy only the n8n application (Service, Deployment).
    *   `--deploy-ingress`: Deploy/Redeploy only the Ingress stack (ManagedCertificate, FrontendConfig, Ingress).
    *   `--update-dns-only`: Only perform the DNS update step (requires Ingress to be up and have an IP).

**Example: Redeploying only the n8n application with force:**
```bash
python scripts/deploy.py --domain your.n8n-domain.com --deploy-n8n --force
```

**Example: Redeploying Ingress and then updating DNS:**
```bash
python scripts/deploy.py --domain your.n8n-domain.com --deploy-ingress --update-dns --force
```

## Post-Deployment

1.  **DNS Propagation:** If you used `--update-dns`, allow time for DNS changes to propagate globally.
2.  **SSL Certificate Provisioning:** Google Managed Certificates can take several minutes (5-20 min, sometimes longer) to provision after the Ingress is up and DNS is pointing to the Ingress IP. You can monitor its status:
    ```bash
    kubectl get managedcertificate n8n-managed-cert -n n8n -o yaml
    ```
    Wait for `certificateStatus` to become `Active`.
3.  **Access n8n:** Once DNS and SSL are ready, access n8n at `https://your.n8n-domain.com`.

## Scaling the GKE Cluster

The `scripts/scale-cluster.ps1` (PowerShell) script can be used to scale your GKE cluster's node pool up or down. This is useful for managing costs when n8n is not actively needed.

**Usage (PowerShell):**
```powershell
# Scale down to 0 nodes (effectively pausing the cluster workloads)
.\scripts\scale-cluster.ps1 -Action down -Project YOUR_GCP_PROJECT -Zone YOUR_GKE_ZONE -ClusterName YOUR_CLUSTER_NAME

# Scale up to 1 node
.\scripts\scale-cluster.ps1 -Action up -NodeCount 1 -Project YOUR_GCP_PROJECT -Zone YOUR_GKE_ZONE -ClusterName YOUR_CLUSTER_NAME
```
*(Note: The file listing shows `scale-cluster.ps1` at the root and in `scripts/`. This README refers to `scripts/scale-cluster.ps1`. Please ensure consistency or clarify which one is canonical.)*

## Troubleshooting

*   **n8n Pods Not Ready:**
    *   `kubectl get pods -n n8n -l service=n8n` (or `app=n8n` depending on final labels in your `n8n-deployment.yaml.template`)
    *   `kubectl describe pod <n8n-pod-name> -n n8n`
    *   `kubectl logs <n8n-pod-name> -n n8n`
    *   Common issues: Database connection problems (check PostgreSQL pods and `postgres-secret`), PVC binding issues, incorrect volumeMounts in `n8n-deployment.yaml.template`.
*   **Ingress IP Not Assigned / Certificate Not Provisioning:**
    *   `kubectl describe ingress n8n-ingress -n n8n` (check Events)
    *   `kubectl get managedcertificate n8n-managed-cert -n n8n -o yaml`
    *   Ensure DNS A record for your domain points to the Ingress IP.
    *   Check GCP Load Balancing and Certificate Manager sections in the Cloud Console for errors.

## Future Work / Roadmap

While the current version is focused on GKE, we plan to enhance this project for broader Kubernetes compatibility and add more features:

*   **Multi-Cloud / Generic Kubernetes Support:**
    *   Integrate support for common Ingress controllers (e.g., Nginx Ingress, Traefik).
    *   Add `cert-manager` integration for SSL certificate management on non-GKE platforms.
    *   Provide more generic StorageClass options or allow easier user specification.
*   **Pluggable Components:** Make components like Ingress controllers, SSL providers, and database types more easily swappable.
*   **Helm Chart:** Potentially package the deployment as a Helm chart for easier installation and management.
*   **Enhanced Configuration:** More options for configuring n8n, PostgreSQL, and resource requests/limits.
*   **UI Wrapper:** Develop a simple web UI or desktop GUI to further simplify the deployment process for end-users.

## License

The deployment scripts and custom configurations in this repository (`https://github.com/neelaryan/n8n-k8s-self-hosting`) are licensed under the **MIT License**. Please see the `LICENSE` file for details.

The base Kubernetes manifests adapted from [n8n-io/n8n-kubernetes-hosting](https://github.com/n8n-io/n8n-kubernetes-hosting) are also provided under an MIT License by n8n.io.

The n8n Community Edition software itself is source-available and uses a "Fair-Code" license (Sustainable Use License by n8n GmbH). Please ensure compliance with all relevant licenses.

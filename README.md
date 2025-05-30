# n8n-kubernetes-hosting

Get up and running with n8n on the following platforms:

* [AWS](https://docs.n8n.io/hosting/server-setups/aws/)
* [Azure](https://docs.n8n.io/hosting/server-setups/azure/)
* [Google Cloud Platform](https://docs.n8n.io/hosting/server-setups/google-cloud/)

If you have questions after trying the tutorials, check out the [forums](https://community.n8n.io/).

## Prerequisites

Self-hosting n8n requires technical knowledge, including:

* Setting up and configuring servers and containers
* Managing application resources and scaling
* Securing servers and applications
* Configuring n8n

n8n recommends self-hosting for expert users. Mistakes can lead to data loss, security issues, and downtime. If you aren't experienced at managing servers, n8n recommends [n8n Cloud](https://n8n.io/cloud/).

## Contributions

For common changes, please open a PR to `main` branch and we will merge this
into cloud provider specific branches.

If you have a contribution specific to a cloud provider, please open your PR to
the relevant branch.

## Deployment Scripts

The `scripts` directory contains `deploy.sh` (for Linux/macOS) and `deploy.ps1` (for Windows PowerShell) to automate the deployment process.

### Force Redeployment

To forcefully redeploy all resources, which involves deleting existing resources before reapplying them, you can use a flag with the deployment scripts:

*   **For `deploy.sh`**:
    ```bash
    ./scripts/deploy.sh -f
    # or
    ./scripts/deploy.sh --force
    ```

*   **For `deploy.ps1`**:
    ```powershell
    .\scripts\deploy.ps1 -Force
    ```

**Caution**: Using the force option will delete existing data in PersistentVolumeClaims if they are deleted and recreated, unless your storage provisioner and reclaim policy are set up to retain data. The current scripts do not delete the StorageClass itself during a force redeploy to avoid impacting other potential applications, but PVCs are deleted and recreated.

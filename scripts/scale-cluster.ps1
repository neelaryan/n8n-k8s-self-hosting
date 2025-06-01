#!/usr/bin/env pwsh

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('up','down')]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$Project,

    [Parameter(Mandatory=$false)]
    [string]$Zone = "asia-south1-a",

    [Parameter(Mandatory=$false)]
    [string]$ClusterName,

    [Parameter(Mandatory=$false)]
    [int]$NodeCount = 1,

    [Parameter(Mandatory=$false)]
    [string]$Namespace = "n8n" # Added Namespace parameter with default
)

# Get project if not provided
if (-not $Project) {
    $Project = gcloud config get-value project
    if (-not $Project) {
        Write-Error "No project specified and couldn't get default project"
        exit 1
    }
}

# Get cluster name if not provided
if (-not $ClusterName) {
    Write-Host "Getting cluster name..."
    $clusters = gcloud container clusters list --project $Project --zone $Zone --format="value(name)"
    if (-not $clusters) {
        Write-Error "No clusters found in project $Project in zone $Zone"
        exit 1
    }
    # If there's only one cluster, use it
    if ($clusters.Count -eq 1) {
        $ClusterName = $clusters
    } else {
        Write-Host "Multiple clusters found. Please specify one:"
        $clusters | ForEach-Object { Write-Host "- $_" }
        exit 1
    }
}

# Function to scale the cluster
function Scale-Cluster {
    param(
        [string]$project,
        [string]$zone,
        [string]$cluster,
        [int]$nodeCount
    )

    Write-Host "Getting node pool name..."
    $nodePool = gcloud container clusters describe $cluster --project $project --zone $zone --format="value(nodePools[0].name)"
    if (-not $nodePool) {
        Write-Error "Could not find node pool for cluster $cluster"
        exit 1
    }

    Write-Host "Scaling node pool $nodePool to $nodeCount nodes..."
    gcloud container clusters resize $cluster `
        --node-pool $nodePool `
        --num-nodes $nodeCount `
        --project $project `
        --zone $zone `
        --quiet

    # If scaling up, wait for nodes to be ready
    if ($nodeCount -gt 0) {
        Write-Host "Waiting for GKE nodes to be ready..."
        # It's good practice to ensure kubectl context is set, though usually it is if gcloud is configured.
        # Consider adding: gcloud container clusters get-credentials $cluster --zone $zone --project $project
        kubectl wait --for=condition=Ready nodes --all --timeout=300s
    }
}

# Main execution
if ($Action -eq 'down') {
    Write-Host "Gracefully scaling down Kubernetes deployments in namespace '$Namespace'..."
    kubectl scale deployment n8n --replicas=0 -n $Namespace
    kubectl scale deployment postgres --replicas=0 -n $Namespace

    # Optional: Add a brief pause or check for pod termination if issues arise
    # Start-Sleep -Seconds 15
    # Write-Host "Verifying pods are terminating..."
    # kubectl get pods -n $Namespace

    Write-Host "Scaling down cluster $ClusterName to 0 nodes..."
    Scale-Cluster -project $Project -zone $Zone -cluster $ClusterName -nodeCount 0
    Write-Host "Cluster $ClusterName scaled down. Workloads in '$Namespace' are at 0 replicas."
} else {
    Write-Host "Scaling up cluster $ClusterName to $NodeCount node(s)..."
    Scale-Cluster -project $Project -zone $Zone -cluster $ClusterName -nodeCount $NodeCount

    # The Scale-Cluster function already waits for nodes if nodeCount > 0

    if ($NodeCount -gt 0) {
        Write-Host "Gracefully scaling up Kubernetes deployments in namespace '$Namespace'..."
        kubectl scale deployment n8n --replicas=1 -n $Namespace
        kubectl scale deployment postgres --replicas=1 -n $Namespace

        Write-Host "Waiting for n8n deployment to be ready..."
        kubectl rollout status deployment/n8n -n $Namespace --timeout=300s
        Write-Host "Waiting for postgres deployment to be ready..."
        kubectl rollout status deployment/postgres -n $Namespace --timeout=300s
        Write-Host "Workloads in '$Namespace' scaled up and deployments are ready."
    } else {
        Write-Host "Cluster $ClusterName remains scaled down (0 nodes). Workloads not scaled up."
    }
}

Write-Host "Script finished."

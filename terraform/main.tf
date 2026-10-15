terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  description = "Google Cloud Project ID hosting the NextGen Editor Agent"
  type        = string
  default     = "nextgen-editor-next27"
}

variable "region" {
  description = "Primary Google Cloud region for Cloud Run and Vertex AI"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Name of the Cloud Run v2 service"
  type        = string
  default     = "nextgen-editor-agent"
}

variable "container_image" {
  description = "Artifact Registry container image for the NextGen Editor Agent"
  type        = string
  default     = "us-central1-docker.pkg.dev/nextgen-editor-next27/agents/nextgen-editor:latest"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Enable Required Google Cloud APIs (Vertex AI, Cloud Run, Secret Manager, Trace, Logging, Discovery Engine, DLP)
resource "google_project_service" "required_apis" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
    "discoveryengine.googleapis.com",
    "dlp.googleapis.com",
  ])

  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# 2. Dedicated Least-Privilege Service Account for NextGen Editor Agent
resource "google_service_account" "agent_sa" {
  account_id   = "${var.service_name}-sa"
  display_name = "NextGen Editor Agent Service Account (Google Cloud Next '27)"
  description  = "Least-privilege identity for NextGen Editor ADK multi-agent runtime"
}

# 3. IAM Roles (Vertex AI, Secret Manager Accessor, Cloud Trace, Cloud Logging, Vertex AI Search, Cloud DLP)
resource "google_project_iam_member" "agent_iam_roles" {
  for_each = toset([
    "roles/aiplatform.user",
    "roles/secretmanager.secretAccessor",
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
    "roles/discoveryengine.viewer",
    "roles/dlp.user",
  ])

  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.agent_sa.email}"
}

# 4. Google Cloud Secret Manager Resources (Category 5.3: Secure Secret Management)
resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = "NEXTGEN_GEMINI_API_KEY"
  project   = var.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

# 5. Cloud Run v2 Service Hosting the NextGen Editor ADK Agent
resource "google_cloud_run_v2_service" "nextgen_editor_agent" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.agent_sa.email

    containers {
      image = var.container_image

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "GOOGLE_GENAI_USE_VERTEXAI"
        value = "TRUE"
      }
      env {
        name = "NEXTGEN_GEMINI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gemini_api_key.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.required_apis,
    google_project_iam_member.agent_iam_roles,
    google_secret_manager_secret.gemini_api_key,
  ]
}

output "cloud_run_service_uri" {
  description = "HTTPS endpoint URL of the deployed NextGen Editor Cloud Run service"
  value       = google_cloud_run_v2_service.nextgen_editor_agent.uri
}

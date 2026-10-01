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
  type    = string
  default = "nextgen-editor-next27"
}

variable "region" {
  type    = string
  default = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_service_account" "nextgen_editor_sa" {
  account_id   = "nextgen-editor-agent-sa"
  display_name = "NextGen Editor — Google Cloud Next '27 Prep Agent SA"
}

resource "google_cloud_run_v2_service" "nextgen_editor_service" {
  name     = "nextgen-editor-agent"
  location = var.region

  template {
    service_account = google_service_account.nextgen_editor_sa.email
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
      env {
        name  = "OTEL_SERVICE_NAME"
        value = "nextgen-editor-agent"
      }
    }
  }
}

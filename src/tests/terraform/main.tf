    service_account = google_service_account.nextgen_editor_sa.email
    containers {
      image = var.container_image
      env {
        name  = "GOOGLE_GENAI_USE_VERTEXAI"
        value = "true"
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "OTEL_SERVICE_NAME"
        value = "nextgen-editor-agent"
      }
    }
  }
  depends_on = [google_project_service.required_apis]
}
Jetski
expires: Oct 5 at 6:06 PM
20261001.01_p0 | 2026.09.29.04

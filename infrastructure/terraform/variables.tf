variable "name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "sieve"
}

variable "environment" {
  type    = string
  default = "production"
}

variable "region" {
  type    = string
  default = "ca-central-1"
}

variable "domain_name" {
  description = "Public host name of the deployment, e.g. sieve.example.com. DNS is managed outside this configuration."
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate for domain_name, in the same region."
  type        = string
}

variable "image_tag" {
  description = "Tag of the backend and web images in ECR (the CI commit SHA). Tags are immutable."
  type        = string
}

# --- network -------------------------------------------------------------------------------

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "az_count" {
  description = "Availability zones to spread subnets over. The load balancer needs at least two."
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3."
  }
}

# --- database and cache --------------------------------------------------------------------

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  type    = number
  default = 20
}

variable "db_multi_az" {
  description = "Off in the cost-conscious profile; turn on for production availability."
  type        = bool
  default     = false
}

variable "db_backup_retention_days" {
  type    = number
  default = 7
}

variable "db_deletion_protection" {
  type    = bool
  default = true
}

variable "enable_redis" {
  description = "Shared rate limiting across API tasks. Without it each task limits on its own."
  type        = bool
  default     = true
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.micro"
}

# --- compute -------------------------------------------------------------------------------

variable "api" {
  type    = object({ cpu = number, memory = number, count = number })
  default = { cpu = 512, memory = 1024, count = 1 }
}

variable "worker" {
  type    = object({ cpu = number, memory = number, count = number, ephemeral_storage_gb = number })
  default = { cpu = 1024, memory = 2048, count = 1, ephemeral_storage_gb = 40 }
}

variable "web" {
  type    = object({ cpu = number, memory = number, count = number })
  default = { cpu = 256, memory = 512, count = 1 }
}

variable "worker_use_spot" {
  description = "Run workers on Fargate Spot. Safe: jobs are idempotent and lease-based, so an interrupted job is re-run."
  type        = bool
  default     = true
}

variable "adot_collector_image" {
  description = "AWS Distro for OpenTelemetry collector sidecar. Pin to a digest before production use."
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
}

# --- application ---------------------------------------------------------------------------

variable "github_app_id" {
  type    = string
  default = null
}

variable "github_app_slug" {
  type    = string
  default = null
}

variable "github_client_id" {
  type    = string
  default = null
}

variable "ai_provider" {
  description = "\"disabled\" or \"anthropic\". When anthropic, the ai-api-key secret must have a value."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["disabled", "anthropic"], var.ai_provider)
    error_message = "ai_provider must be \"disabled\" or \"anthropic\"."
  }
}

variable "ai_model" {
  type    = string
  default = "claude-opus-5-5"
}

variable "ai_daily_budget_usd" {
  type    = number
  default = 5
}

# --- operations ----------------------------------------------------------------------------

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "alarm_email" {
  description = "Receives CloudWatch alarm notifications. Null creates the topic without a subscriber."
  type        = string
  default     = null
}

variable "github_repository" {
  description = "owner/name of the repository whose main branch may deploy through GitHub OIDC. Null skips the CI role."
  type        = string
  default     = null
}

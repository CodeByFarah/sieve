locals {
  public_url  = "https://${var.domain_name}"
  backend_img = "${aws_ecr_repository.this["backend"].repository_url}:${var.image_tag}"
  web_img     = "${aws_ecr_repository.this["web"].repository_url}:${var.image_tag}"

  backend_env_map = {
    SIEVE_ENVIRONMENT                 = "production"
    SIEVE_LOG_JSON                    = "true"
    SIEVE_ARTIFACT_BACKEND            = "s3"
    SIEVE_S3_BUCKET                   = aws_s3_bucket.artifacts.bucket
    SIEVE_AWS_REGION                  = var.region
    SIEVE_PUBLIC_WEB_URL              = local.public_url
    SIEVE_PUBLIC_API_URL              = local.public_url
    SIEVE_CORS_ORIGINS                = jsonencode([local.public_url])
    SIEVE_GITHUB_APP_ID               = var.github_app_id
    SIEVE_GITHUB_APP_SLUG             = var.github_app_slug
    SIEVE_GITHUB_CLIENT_ID            = var.github_client_id
    SIEVE_AI_PROVIDER                 = var.ai_provider
    SIEVE_AI_MODEL                    = var.ai_model
    SIEVE_AI_DAILY_BUDGET_USD         = tostring(var.ai_daily_budget_usd)
    SIEVE_REDIS_URL                   = var.enable_redis ? "rediss://${aws_elasticache_replication_group.main[0].primary_endpoint_address}:6379/0" : null
    SIEVE_OTEL_EXPORTER_OTLP_ENDPOINT = "http://127.0.0.1:4318"
  }
  backend_environment = [for k, v in local.backend_env_map : { name = k, value = v } if v != null]

  backend_secrets = concat(
    [{ name = "SIEVE_DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn }],
    [for key, secret in aws_secretsmanager_secret.external : { name = "SIEVE_${upper(key)}", valueFrom = secret.arn }],
  )

  scratch_mount = [{ sourceVolume = "scratch", containerPath = "/scratch", readOnly = false }]

  # Receives OTLP from the application on 127.0.0.1:4318 and forwards traces to X-Ray and metrics
  # to CloudWatch (embedded metric format), using the configuration shipped in the image.
  otel_sidecar = {
    name                   = "otel-collector"
    image                  = var.adot_collector_image
    essential              = false
    command                = ["--config=/etc/ecs/ecs-default-config.yaml"]
    readonlyRootFilesystem = false
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.service["otel"].name
        awslogs-region        = var.region
        awslogs-stream-prefix = "otel"
      }
    }
  }

  api_health_probe = "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
}

resource "aws_cloudwatch_log_group" "service" {
  for_each          = toset(["api", "worker", "web", "migrate", "otel"])
  name              = "/ecs/${var.name}/${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "main" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  service_connect_defaults {
    namespace = aws_service_discovery_http_namespace.main.arn
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]
}

# Lets the web tasks reach the API at http://api:8000 without going back out through the ALB.
resource "aws_service_discovery_http_namespace" "main" {
  name = "${var.name}.internal"
}

# --- task definitions ----------------------------------------------------------------------

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api.cpu
  memory                   = var.api.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.backend_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "scratch"
  }

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = local.backend_img
      essential = true
      # Behind the ALB: trust X-Forwarded-For so rate limits see the client, not the balancer.
      # Safe with "*" because the security group admits only the ALB and the web tasks.
      command = [
        "uvicorn", "sieve.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000",
        "--proxy-headers", "--forwarded-allow-ips", "*",
      ]
      portMappings           = [{ name = "api", containerPort = 8000, protocol = "tcp", appProtocol = "http" }]
      readonlyRootFilesystem = true
      mountPoints            = local.scratch_mount
      environment            = local.backend_environment
      secrets                = local.backend_secrets
      healthCheck = {
        command     = ["CMD", "python", "-c", local.api_health_probe]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["api"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "api"
        }
      }
    },
    local.otel_sidecar,
  ])
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.name}-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker.cpu
  memory                   = var.worker.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.backend_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  # Holds the PyPI package cache; lost when the task is replaced (the next scan is cold).
  ephemeral_storage {
    size_in_gib = var.worker.ephemeral_storage_gb
  }

  volume {
    name = "scratch"
  }

  container_definitions = jsonencode([
    {
      name                   = "worker"
      image                  = local.backend_img
      essential              = true
      command                = ["python", "-m", "sieve.worker"]
      readonlyRootFilesystem = true
      mountPoints            = local.scratch_mount
      environment            = local.backend_environment
      secrets                = local.backend_secrets
      # After SIGTERM the worker finishes its current job, then exits. A job cut off when this
      # runs out is re-run once its lease expires.
      stopTimeout = 120
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["worker"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "worker"
        }
      }
    },
    local.otel_sidecar,
  ])
}

# One-off: run before each release (see docs/deployment.md). Not a service.
resource "aws_ecs_task_definition" "migrate" {
  family                   = "${var.name}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.backend_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "scratch"
  }

  container_definitions = jsonencode([
    {
      name                   = "migrate"
      image                  = local.backend_img
      essential              = true
      command                = ["alembic", "upgrade", "head"]
      readonlyRootFilesystem = true
      mountPoints            = local.scratch_mount
      environment            = local.backend_environment
      secrets                = [local.backend_secrets[0]]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["migrate"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "migrate"
        }
      }
    },
  ])
}

resource "aws_ecs_task_definition" "web" {
  family                   = "${var.name}-web"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.web.cpu
  memory                   = var.web.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.web_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "scratch"
  }

  volume {
    name = "next-cache"
  }

  container_definitions = jsonencode([
    {
      name                   = "web"
      image                  = local.web_img
      essential              = true
      portMappings           = [{ name = "web", containerPort = 3000, protocol = "tcp", appProtocol = "http" }]
      readonlyRootFilesystem = true
      mountPoints = concat(local.scratch_mount, [
        { sourceVolume = "next-cache", containerPath = "/web/.next/cache", readOnly = false },
      ])
      # The image is built with SIEVE_API_URL=http://api:8000 (rewrites are fixed at build time);
      # server-side rendering reads the same value at run time.
      environment = [{ name = "SIEVE_API_URL", value = "http://api:8000" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["web"].name
          awslogs-region        = var.region
          awslogs-stream-prefix = "web"
        }
      }
    },
  ])
}

# --- services ------------------------------------------------------------------------------

resource "aws_ecs_service" "api" {
  name                              = "api"
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.api.arn
  desired_count                     = var.api.count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }

  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.main.arn
    service {
      port_name      = "api"
      discovery_name = "api"
      client_alias {
        port     = 8000
        dns_name = "api"
      }
    }
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # image_tag sets the first image; later releases are rolled out by .github/workflows/deploy.yml,
  # which registers new task definition revisions. Terraform must not roll them back.
  lifecycle {
    ignore_changes = [task_definition]
  }

  depends_on = [aws_lb_listener_rule.api]
}

resource "aws_ecs_service" "worker" {
  name            = "worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker.count

  capacity_provider_strategy {
    capacity_provider = var.worker_use_spot ? "FARGATE_SPOT" : "FARGATE"
    weight            = 1
  }

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.worker.id]
    assign_public_ip = true
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [task_definition]
  }

  depends_on = [aws_ecs_cluster_capacity_providers.main]
}

resource "aws_ecs_service" "web" {
  name                              = "web"
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.web.arn
  desired_count                     = var.web.count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.web.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.web.arn
    container_name   = "web"
    container_port   = 3000
  }

  # Client only: lets web resolve http://api:8000.
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.main.arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [task_definition]
  }

  depends_on = [aws_lb_listener.https]
}

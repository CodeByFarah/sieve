# --- PostgreSQL ------------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "postgres16" {
  name   = "${var.name}-postgres16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }
}

resource "random_password" "database" {
  length  = 40
  special = false
}

resource "aws_db_instance" "main" {
  identifier                   = var.name
  engine                       = "postgres"
  engine_version               = "16"
  instance_class               = var.db_instance_class
  allocated_storage            = var.db_allocated_storage_gb
  max_allocated_storage        = var.db_allocated_storage_gb * 5
  storage_type                 = "gp3"
  storage_encrypted            = true
  db_name                      = "sieve"
  username                     = "sieve"
  password                     = random_password.database.result
  db_subnet_group_name         = aws_db_subnet_group.main.name
  parameter_group_name         = aws_db_parameter_group.postgres16.name
  vpc_security_group_ids       = [aws_security_group.database.id]
  multi_az                     = var.db_multi_az
  publicly_accessible          = false
  backup_retention_period      = var.db_backup_retention_days
  deletion_protection          = var.db_deletion_protection
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${var.name}-final"
  auto_minor_version_upgrade   = true
  performance_insights_enabled = true
  copy_tags_to_snapshot        = true
}

# --- Redis (rate limiting) -------------------------------------------------------------------

resource "aws_elasticache_subnet_group" "main" {
  count      = var.enable_redis ? 1 : 0
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_replication_group" "main" {
  count                      = var.enable_redis ? 1 : 0
  replication_group_id       = var.name
  description                = "Sieve rate limits"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 1
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.main[0].name
  security_group_ids         = [aws_security_group.redis[0].id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}

# --- secrets -----------------------------------------------------------------------------------
# The database URL is assembled here (so its password is in Terraform state; keep state encrypted
# and access-controlled). Every other secret is created empty and given its value out of band:
#   aws secretsmanager put-secret-value --secret-id <arn> --secret-string file://value
# ECS refuses to start a task whose referenced secret has no value, so set them before deploying.

resource "aws_secretsmanager_secret" "database_url" {
  name                    = "${var.name}/database-url"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id     = aws_secretsmanager_secret.database_url.id
  secret_string = "postgresql+psycopg://sieve:${random_password.database.result}@${aws_db_instance.main.address}:5432/sieve?sslmode=require"
}

locals {
  external_secrets = merge(
    {
      github_private_key    = "github-private-key"
      github_webhook_secret = "github-webhook-secret"
      github_client_secret  = "github-client-secret"
    },
    var.ai_provider == "anthropic" ? { ai_api_key = "ai-api-key" } : {},
  )
}

resource "aws_secretsmanager_secret" "external" {
  for_each                = local.external_secrets
  name                    = "${var.name}/${each.value}"
  recovery_window_in_days = 7
}

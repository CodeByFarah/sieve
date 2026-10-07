output "load_balancer_dns_name" {
  description = "Point the DNS record for domain_name here (CNAME or alias)."
  value       = aws_lb.main.dns_name
}

output "ecr_repositories" {
  value = { for k, repo in aws_ecr_repository.this : k => repo.repository_url }
}

output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "migrate_task_definition" {
  description = "Run once per release, before updating services."
  value       = aws_ecs_task_definition.migrate.family
}

output "task_network" {
  description = "Network settings for aws ecs run-task (migrations)."
  value = {
    subnets         = aws_subnet.public[*].id
    security_groups = [aws_security_group.worker.id]
  }
}

output "artifacts_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}

output "secrets_to_populate" {
  description = "Secrets created without a value. Set each before the first deploy."
  value       = { for k, s in aws_secretsmanager_secret.external : k => s.arn }
}

output "ci_deploy_role_arn" {
  value = local.ci_enabled ? aws_iam_role.ci_deploy[0].arn : null
}

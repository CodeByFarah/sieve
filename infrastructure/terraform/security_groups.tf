resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Public HTTPS entry point"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  description       = "Redirected to HTTPS"
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "alb_to_vpc" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "-1"
}

# One group per role. Tasks accept traffic only from the load balancer (and web to api over
# Service Connect). Egress is open because workers fetch from PyPI, OSV, GitHub, CISA and FIRST;
# the destination allow-list is enforced in the HTTP client of the application (threat model 3.5).
resource "aws_security_group" "api" {
  name        = "${var.name}-api"
  description = "API tasks"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "web" {
  name        = "${var.name}-web"
  description = "Web tasks"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "worker" {
  name        = "${var.name}-worker"
  description = "Worker and migration tasks, no inbound traffic"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "api_from_alb" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
}

resource "aws_vpc_security_group_ingress_rule" "api_from_web" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = aws_security_group.web.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
}

resource "aws_vpc_security_group_ingress_rule" "web_from_alb" {
  security_group_id            = aws_security_group.web.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 3000
  to_port                      = 3000
}

# Outbound: HTTPS anywhere (PyPI, GitHub, OSV, CISA, FIRST, and the AWS APIs that Fargate reaches
# through the task network: ECR, Secrets Manager, CloudWatch), plus anything inside the VPC
# (database, cache, Service Connect). Which HTTPS hosts are allowed is enforced by the application.
# Destinations are dynamic public hosts; see threat model 3.5 and 6.
#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "tasks_https" {
  for_each = {
    api    = aws_security_group.api.id
    web    = aws_security_group.web.id
    worker = aws_security_group.worker.id
  }
  security_group_id = each.value
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "tasks_vpc" {
  for_each = {
    api    = aws_security_group.api.id
    web    = aws_security_group.web.id
    worker = aws_security_group.worker.id
  }
  security_group_id = each.value
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "-1"
}

resource "aws_security_group" "database" {
  name        = "${var.name}-database"
  description = "PostgreSQL, reachable from API and worker tasks only"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "database_from_tasks" {
  for_each = {
    api    = aws_security_group.api.id
    worker = aws_security_group.worker.id
  }
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_security_group" "redis" {
  count       = var.enable_redis ? 1 : 0
  name        = "${var.name}-redis"
  description = "Rate-limit store, reachable from API tasks only"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_api" {
  count                        = var.enable_redis ? 1 : 0
  security_group_id            = aws_security_group.redis[0].id
  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
}

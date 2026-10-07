# Alarms on the signals ADR-0012 names: error rate, dead jobs, scan failures, and the health of
# the database and load balancer. Application signals come from the JSON logs through metric
# filters, so they work without any extra agent.

# CloudWatch alarms cannot publish to a topic encrypted with the AWS-managed SNS key, and alarm
# messages carry no sensitive data. Use a customer-managed key if that changes.
#trivy:ignore:AVD-AWS-0095
resource "aws_sns_topic" "alarms" {
  name = "${var.name}-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == null ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  alarm_actions = [aws_sns_topic.alarms.arn]

  log_signals = {
    DeadJobs = {
      log_group = aws_cloudwatch_log_group.service["worker"].name
      pattern   = "{ $.event = \"job.failed\" && $.new_status = \"dead\" }"
      threshold = 1
      period    = 300
      summary   = "A job exhausted its retries and moved to the dead-letter state."
    }
    ScanFailures = {
      log_group = aws_cloudwatch_log_group.service["worker"].name
      pattern   = "{ $.event = \"job.failed\" && $.kind = \"scan.run\" }"
      threshold = 3
      period    = 900
      summary   = "Several scan attempts failed within 15 minutes."
    }
    UnhandledApiErrors = {
      log_group = aws_cloudwatch_log_group.service["api"].name
      pattern   = "{ $.event = \"request.unhandled_exception\" }"
      threshold = 5
      period    = 300
      summary   = "The API raised unhandled exceptions."
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "signal" {
  for_each       = local.log_signals
  name           = each.key
  log_group_name = each.value.log_group
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = "Sieve"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "signal" {
  for_each            = local.log_signals
  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.summary
  namespace           = "Sieve"
  metric_name         = each.key
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
  depends_on          = [aws_cloudwatch_log_metric_filter.signal]
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.name}-target-5xx"
  alarm_description   = "Services returned 5xx responses through the load balancer."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = { LoadBalancer = aws_lb.main.arn_suffix }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  for_each = {
    api = aws_lb_target_group.api.arn_suffix
    web = aws_lb_target_group.web.arn_suffix
  }
  alarm_name          = "${var.name}-${each.key}-unhealthy"
  alarm_description   = "The ${each.key} service has unhealthy targets."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = { LoadBalancer = aws_lb.main.arn_suffix, TargetGroup = each.value }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 5
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "${var.name}-database-cpu"
  alarm_description   = "Database CPU above 80% for 15 minutes."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.main.identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "database_storage" {
  alarm_name          = "${var.name}-database-storage"
  alarm_description   = "Less than 2 GB of database storage left."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.main.identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 2 * 1024 * 1024 * 1024
  comparison_operator = "LessThanThreshold"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

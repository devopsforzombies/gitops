

resource "helm_release" "argocd" {
  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"

  chart      = "argo-cd"
  version    = "5.37.1"
  namespace = "argocd"
  create_namespace = true

  set {
    name  = "server.service.type"
    value =  "LoadBalancer"
  }

  set {
    name  = "server.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-backend-protocol"
    value =  "https"
  }

  set {
    name  = "server.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-cert"
    value =  var.acm_certificate_arn
  }

  set {
    name  = "server.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-ports"
    value = "https"
  }

  set {
    name  = "server.service.annotations.external-dns\\.alpha\\.kubernetes\\.io/hostname"
    value = "argocd.${var.domain_name}"
  }


  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.iam_role.arn
  }

  set {
    name  = "server.config.url"
    value = "https://${var.domain_name}"
  }

  set {
    name  = "server.config.kustomize\\.path\\.default"
    value = "/usr/local/bin/kustomize"
  }

  set {
    name  = "server.env[0].name"
    value = "ARGOCD_AUTH_TOKEN"
  }

  set {
    name  = "accounts.admin.enabled"
    value = "true"
  }

  set {
    name  = "accounts.crossplane"
    value = "apiKey"
  }


  set {
    name  = "accounts.crossplane.enabled"
    value = "true"
  }

  set {
    name  = "server.env[0].value"
    value = random_password.admin_token.result
  }


  set {
    name  = "server.env[0].value"
    value = random_password.admin_token.result
  }

  set {
    name  = "configs.secret.argocdServerAdminPassword"
    value = htpasswd_password.hash.bcrypt
  }

  set {
    name  = "configs.credentialTemplates.ssh-creds.url"
    value = "git@github.com:devopsforzombies"
  }


  set {
    name  = "redis.enabled"
    value = false
  }

  set {
    name  = "externalRedis.host"
    value = aws_elasticache_replication_group.redis.primary_endpoint_address
  }
}

resource "random_password" "password" {
  length = 30
}

resource "random_password" "admin_token" {
  length = 30
  special          = false
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "random_password" "salt" {
  length = 8
}

resource "htpasswd_password" "hash" {
  password = random_password.password.result
  salt     = random_password.salt.result
}


data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}


# Add passwords on AWS Secrets
resource "aws_secretsmanager_secret" "argocd" {
  name = "/gitops/argocd"
  description = "ArgoCD login"
}

resource "aws_secretsmanager_secret_version" "argocd" {
  secret_id = aws_secretsmanager_secret.argocd.id
  secret_string = jsonencode({
    "login" = "admin",
    "password" = random_password.password.result
    "admin_token" = random_password.admin_token.result
  })

}

# aws_elasticache_replication_group_redis
resource "aws_elasticache_replication_group" "redis" {
    apply_immediately             = true
    at_rest_encryption_enabled    = false
    auto_minor_version_upgrade    = true
    automatic_failover_enabled    = true
    engine                        = "redis"
    engine_version                = "5.0.6"
    maintenance_window            = "sun:11:00-sun:12:00"
    node_type                     = "cache.t3.micro"
    parameter_group_name          = aws_elasticache_parameter_group.redis.name
    port                          = 6379
    replication_group_description = "argocd redis"
    replication_group_id          = "argocd"
    security_group_ids            = [
        aws_security_group.redis.id
    ]
    security_group_names          = []
    snapshot_retention_limit      = 1
    snapshot_window               = "01:00-02:00"
    subnet_group_name             = aws_elasticache_subnet_group.redis.name
    tags        = {
                  "Name": "argocd-redis",
                  "managed-by" : "terraform"
                 }
    transit_encryption_enabled    = false

    cluster_mode {
      replicas_per_node_group = 1
      num_node_groups         = 1
    }

    timeouts {}
}


# aws_elasticache_parameter_group.redis:
resource "aws_elasticache_parameter_group" "redis" {
    description = "argocd-redis"
    family      = "redis5.0"
    name        = "argocd-redis"
}



# aws_elasticache_subnet_group.redis:
resource "aws_elasticache_subnet_group" "redis" {
    description = "argocd-redis subnet group"
    name        = "argocd-redis"
    subnet_ids  = var.vpc_private_subnets
}

# aws_security_group.redis:
resource "aws_security_group" "redis" {
    description = "Allows services Redis Traffic from other VPCs"
    egress      = [
        {
            cidr_blocks      = [
                "0.0.0.0/0",
            ]
            description      = ""
            from_port        = 0
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "-1"
            security_groups  = []
            self             = false
            to_port          = 0
        },
    ]
    ingress     = [
        {
            cidr_blocks      = [
                var.vpc_cidr
            ]
            description      = "FROM K8S Clusters"
            from_port        = 6379
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = []
            self             = false
            to_port          = 6379
        },
    ]
    name        = "argocd-redis"
    tags        = {
                  "Name": "argocd-redis",
                  "managed-by" : "terraform"
                 }
    vpc_id      = var.vpc_id

    timeouts {}
}


data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringLike"
      variable = "${var.oidc_provider}:sub"
      values   = ["system:serviceaccount:argocd:argocd-*"]
    }

    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.id}:oidc-provider/${var.oidc_provider}"]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "iam_role" {
  name                  = "argocd"
  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy.json
  force_detach_policies = true
}


resource "aws_iam_policy" "argocd" {
  name = "argocd"
  path        = "/"
  description = "argocd policy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::${data.aws_caller_identity.current.id}:role/${aws_iam_role.iam_role.name}"
        }
    ]
}
EOF
}

resource "aws_iam_policy_attachment" "argocd" {
  name       = "argocd"
  roles      = [aws_iam_role.iam_role.name]
  policy_arn = aws_iam_policy.argocd.arn
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}


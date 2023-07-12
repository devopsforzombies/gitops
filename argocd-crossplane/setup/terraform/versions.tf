terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "< 4.0.0"
    }
    helm = {
      source = "hashicorp/helm"
      version = "2.4.1"
    }
    argocd = {
      source = "oboukili/argocd"
      version = "3.0.1"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "2.11.0"
    }
    kubectl = {
      source = "gavinbunney/kubectl"
      version = "1.14.0"
    }
    htpasswd = {
      source = "loafoe/htpasswd"
    }
  }
  required_version = ">= 0.13, < 2.0"
}

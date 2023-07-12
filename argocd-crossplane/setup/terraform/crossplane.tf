locals { 
  crossplane-providers = [
    "crossplane/provider-helm:v0.15.0"
  ]
}

resource "helm_release" "crossplane" {
  name       = "crossplane"
  repository = "https://charts.crossplane.io/stable"

  chart      = "crossplane"
  version    = "1.12.0"
  namespace = "crossplane-system"
  create_namespace = true

  set {
    name  = "provider.packages"
    value =  "{${join(",", local.crossplane-providers)}}"
  }

  set {
    name  = "args"
    value =  "{--enable-composition-revisions}"
  }

}

data "aws_iam_policy_document" "crossplane" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringLike"
      variable = "${var.oidc_provider}:sub"
      values   = ["system:serviceaccount:crossplane-system:*"]
    }

    principals {
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.id}:oidc-provider/${var.oidc_provider}"]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "crossplane" {
  name                  = "argocd-gitops-crossplane"
  assume_role_policy    = data.aws_iam_policy_document.crossplane.json
  force_detach_policies = true
}

resource "aws_iam_role_policy" "crossplane" {
  name = "argocd-gitops-crossplane"
  role = aws_iam_role.crossplane.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


resource "kubectl_manifest" "argocd-crossplane-secrets" {
  force_new = true
  yaml_body = <<YAML
    apiVersion: v1
    data:
      username: YWRtaW4=
      password: ${base64encode(random_password.password.result)}
      admin_token: ${base64encode(random_password.admin_token.result)}
    kind: Secret
    metadata:
      name: argocd-crossplane-token
      namespace: crossplane-system
    type: Opaque
  YAML
}


resource "kubectl_manifest" "cross-plane-aws-controller-conf" {
  yaml_body = <<YAML
    apiVersion: pkg.crossplane.io/v1alpha1
    kind: ControllerConfig
    metadata:
      name: aws-config
      namespace: "crossplane-system"
      annotations:
        eks.amazonaws.com/role-arn: ${aws_iam_role.crossplane.arn}"
    spec:
      podSecurityContext:
        fsGroup: 2000
      args:
      - '--debug'
  YAML
}

resource "kubectl_manifest" "cross-plane-controller-debug-conf" {
  yaml_body = <<YAML
    apiVersion: pkg.crossplane.io/v1alpha1
    kind: ControllerConfig
    metadata:
      name: debug-config
      namespace: "crossplane-system"
    spec:
      args:
      - '--debug'
  YAML
}



resource "kubectl_manifest" "cross-plane-aws-provider-conf" {
  yaml_body = <<YAML
    apiVersion: aws.crossplane.io/v1beta1
    kind: ProviderConfig
    metadata:
      name: default
      namespace: "crossplane-system"
    spec:
      credentials:
        source: InjectedIdentity
  YAML
}

resource "kubectl_manifest" "cross-plane-kubernetes-provider-conf" {
  yaml_body = <<YAML
    apiVersion: kubernetes.crossplane.io/v1alpha1
    kind: ProviderConfig
    metadata:
      name: default
      namespace: "crossplane-system"
    spec:
      credentials:
        source: InjectedIdentity
  YAML
}

resource "kubectl_manifest" "cross-plane-kubernetes-provider" {
  yaml_body = <<YAML
  apiVersion: pkg.crossplane.io/v1
  kind: Provider
  metadata:
    name: provider-kubernetes
  spec:
    package: "crossplane/provider-kubernetes:main"
  YAML
}

resource "kubectl_manifest" "cross-plane-aws-provider" {
  yaml_body = <<YAML
    apiVersion: pkg.crossplane.io/v1
    kind: Provider
    metadata:
      name: aws-provider
      namespace: "crossplane-system"
    spec:
      ignoreCrossplaneConstraints: false
      package: crossplane/provider-aws:v0.32.0
      packagePullPolicy: IfNotPresent
      revisionActivationPolicy: Automatic
      revisionHistoryLimit: 1
      skipDependencyResolution: false
  YAML
}


resource "kubectl_manifest" "argocd-crossplane-provider" {
  yaml_body = <<YAML
      apiVersion: pkg.crossplane.io/v1
      kind: Provider
      metadata:
        name: argocd-provider
        namespace: crossplane-system
        annotations:
          company: argocd-gitops
          maintainer: Crossplane Maintainers <info@crossplane.io>
          source: github.com/crossplane-contrib/provider-argocd
          license: Apache-2.0
          descriptionShort: |
            The argocd Crossplane provider enables resources management for argocd.
          description: |
            The argocd Crossplane provider adds support for
            managing argocd resources in Kubernetes.
          readme: |
            `provider-argocd` is the Crossplane infrastructure provider for
            [argocd](https://argocd.com/).
            Available resources and their fields can be found in the [CRD
            Docs](https://doc.crds.dev/github.com/crossplane-contrib/provider-argocd).
            If you encounter an issue please reach out on
            [slack.crossplane.io](https://slack.crossplane.io) and create an issue in
            the [crossplane-contrib/provider-argocd](https://github.com/crossplane-contrib/provider-argocd)
            repo.
      spec:
        ignoreCrossplaneConstraints: false
        package: xpkg.upbound.io/crossplane-contrib/provider-argocd:v0.3.0
        packagePullPolicy: IfNotPresent
        revisionActivationPolicy: Automatic
        revisionHistoryLimit: 1
        skipDependencyResolution: false
  YAML
}

## ARGOCD CROSSPLANE

resource "kubectl_manifest" "argocd-crossplane-provider-config" {
  yaml_body = <<YAML
    # argocd provider that references the secret credentials
    apiVersion: argocd.crossplane.io/v1alpha1
    kind: ProviderConfig
    metadata:
      name: argocd-provider
      namespace: crossplane-system
    spec:
      serverAddr: argocd.argocd-gitops.cloud:443
      insecure: true
      plainText: false
      credentials:
        source: Secret
        secretRef:
          namespace: crossplane-system
          name: argocd-crossplane-token
          key: admin_token
  YAML
  depends_on = [helm_release.crossplane]
}

resource "kubectl_manifest" "cross-plane-aws-provider-conf" {
  force_new = true
  yaml_body = <<YAML
    apiVersion: aws.crossplane.io/v1beta1
    kind: ProviderConfig
    metadata:
      name: gitops-aws-account
      namespace: "crossplane-system"
    spec:
      assumeRoleWithWebIdentity:
        roleARN: "${aws_iam_role.crossplane.arn}"
        roleSessionName: "crossplane"
      credentials:
        source: InjectedIdentity
  YAML
}


resource "kubectl_manifest" "cross-plane-argocd-controller-conf" {
  yaml_body = <<YAML
    apiVersion: pkg.crossplane.io/v1alpha1
    kind: ControllerConfig
    metadata:
      name: argocd-conf
      namespace: "crossplane-system"
    spec:
     args:
     - '--debug'
  YAML
}


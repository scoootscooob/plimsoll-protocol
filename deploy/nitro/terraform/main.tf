# Plimsoll Nitro Enclave — Terraform deployment for AWS.
#
# Creates a VPC with private subnet, an EC2 instance with Nitro Enclave
# support, IAM roles for PCR0-attested KMS access, optional dedicated
# KMS CMK, and a VPC endpoint for KMS (no internet needed).
#
# The private key NEVER exists on the host OS.  The enclave authenticates
# to KMS using its PCR0 hash (SHA-384 of the enclave image).  KMS only
# releases the data key to the attested enclave.
#
# Usage:
#   terraform init
#   terraform plan -var="key_pair_name=my-key" -var="enclave_pcr0=<hash>"
#   terraform apply -var="key_pair_name=my-key" -var="enclave_pcr0=<hash>"

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── VPC ──────────────────────────────────────────────────────────

resource "aws_vpc" "plimsoll" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "plimsoll-nitro-vpc"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.plimsoll.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "plimsoll-nitro-private"
  }
}

# ── VPC Endpoint for KMS (no internet required) ─────────────────
# The enclave communicates with KMS via a VPC interface endpoint.
# This eliminates the need for NAT gateway or internet gateway —
# KMS traffic stays entirely within the AWS network.

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.plimsoll.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.plimsoll_enclave.id]
  private_dns_enabled = true

  tags = {
    Name = "plimsoll-kms-endpoint"
  }
}

# ── Security Group ───────────────────────────────────────────────

resource "aws_security_group" "plimsoll_enclave" {
  name_prefix = "plimsoll-enclave-"
  vpc_id      = aws_vpc.plimsoll.id

  # No inbound access from the internet (enclave is isolated)
  # Outbound: HTTPS only — KMS VPC endpoint
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "HTTPS to KMS VPC endpoint (private)"
  }

  # Self-referencing rule for VPC endpoint ENI communication
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    self        = true
    description = "KMS VPC endpoint interface"
  }

  tags = {
    Name = "plimsoll-enclave-sg"
  }
}

# ── KMS Key (optional — created if var.create_kms_key is true) ──
# A dedicated CMK with a key policy that ONLY allows Decrypt and
# GenerateDataKey when the caller presents an attestation document
# with the expected PCR0 hash.  Even an AWS admin cannot decrypt
# without the enclave.

resource "aws_kms_key" "plimsoll_enclave" {
  count               = var.create_kms_key ? 1 : 0
  description         = "Plimsoll Nitro Enclave signing key — PCR0-gated"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "plimsoll-enclave-key-policy"
    Statement = [
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEnclaveDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.plimsoll_enclave.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.enclave_pcr0
          }
        }
      },
      {
        Sid    = "DenyDecryptWithoutAttestation"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          Null = {
            "kms:RecipientAttestation:PCR0" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Name = "plimsoll-enclave-cmk"
  }
}

resource "aws_kms_alias" "plimsoll_enclave" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/plimsoll-enclave-signing-key"
  target_key_id = aws_kms_key.plimsoll_enclave[0].key_id
}

data "aws_caller_identity" "current" {}

# ── IAM Role ─────────────────────────────────────────────────────

resource "aws_iam_role" "plimsoll_enclave" {
  name = "plimsoll-nitro-enclave-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "kms_access" {
  name = "plimsoll-kms-access"
  role = aws_iam_role.plimsoll_enclave.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowKMSWithAttestation"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = local.kms_key_arn != "" ? [local.kms_key_arn] : ["*"]
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.enclave_pcr0
          }
        }
      },
      {
        Sid      = "AllowS3BlobStorage"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = var.encrypted_blob_s3_bucket != "" ? ["arn:aws:s3:::${var.encrypted_blob_s3_bucket}/plimsoll/*"] : ["arn:aws:s3:::dummy/*"]
      }
    ]
  })
}

locals {
  kms_key_arn = var.create_kms_key ? aws_kms_key.plimsoll_enclave[0].arn : var.kms_key_arn
}

resource "aws_iam_instance_profile" "plimsoll_enclave" {
  name = "plimsoll-nitro-enclave-profile"
  role = aws_iam_role.plimsoll_enclave.name
}

# ── EC2 Instance ─────────────────────────────────────────────────

resource "aws_instance" "plimsoll_enclave" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_pair_name
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.plimsoll_enclave.id]
  iam_instance_profile   = aws_iam_instance_profile.plimsoll_enclave.name

  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail

    # ── Install Nitro Enclaves CLI ─────────────────────────────
    yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
    systemctl enable nitro-enclaves-allocator.service
    systemctl start nitro-enclaves-allocator.service

    # ── Configure enclave allocator ────────────────────────────
    # Reserve 512 MB for the enclave (must be <= instance memory - 1GB)
    cat > /etc/nitro_enclaves/allocator.yaml <<ALLOCATOR
    ---
    memory_mib: 512
    cpu_count: 2
    ALLOCATOR
    systemctl restart nitro-enclaves-allocator.service

    # ── Set environment for KMS bootstrap ──────────────────────
    mkdir -p /opt/plimsoll
    cat > /opt/plimsoll/enclave.env <<ENVFILE
    PLIMSOLL_KMS_KEY_ARN=${local.kms_key_arn}
    AWS_REGION=${var.aws_region}
    PLIMSOLL_ENCLAVE_PCR0=${var.enclave_pcr0}
    PLIMSOLL_KEY_PROVIDER=${var.key_provider}
    ENVFILE

    # ── Build and run the enclave ──────────────────────────────
    # The EIF (Enclave Image File) is pre-built and stored at /opt/plimsoll/plimsoll.eif
    # Build command: nitro-cli build-enclave --docker-uri plimsoll-enclave:latest --output-file plimsoll.eif
    nitro-cli run-enclave \
      --eif-path /opt/plimsoll/plimsoll.eif \
      --memory 512 \
      --cpu-count 2

    echo "Plimsoll Nitro Enclave running — PCR0-attested KMS bootstrap active"
  EOF

  tags = {
    Name = "plimsoll-nitro-enclave"
  }
}

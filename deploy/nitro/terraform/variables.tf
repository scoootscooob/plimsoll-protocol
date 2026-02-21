# Aegis Nitro Enclave — Terraform variables.

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type (must support Nitro Enclaves)"
  type        = string
  default     = "m5.xlarge"
}

variable "ami_id" {
  description = "Amazon Linux 2 AMI ID (use latest for your region)"
  type        = string
  default     = "ami-0c02fb55956c7d316" # Amazon Linux 2 us-east-1
}

variable "key_pair_name" {
  description = "EC2 key pair name for SSH access"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS CMK used for PCR0-attested key wrapping"
  type        = string
  default     = ""
}

variable "enclave_pcr0" {
  description = "PCR0 hash (SHA-384) of the enclave image — gates KMS access"
  type        = string
  default     = ""
}

variable "create_kms_key" {
  description = "If true, create a dedicated KMS CMK with PCR0 attestation policy"
  type        = bool
  default     = false
}

variable "key_provider" {
  description = "Key management provider: 'kms' (AWS KMS) or 'turnkey' (MPC)"
  type        = string
  default     = "kms"

  validation {
    condition     = contains(["kms", "turnkey"], var.key_provider)
    error_message = "key_provider must be 'kms' or 'turnkey'"
  }
}

variable "encrypted_blob_s3_bucket" {
  description = "S3 bucket for storing the encrypted key blob (optional, defaults to local EBS)"
  type        = string
  default     = ""
}

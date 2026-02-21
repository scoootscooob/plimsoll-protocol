# Plimsoll Nitro Enclave — Terraform outputs.

output "instance_id" {
  description = "EC2 instance ID running the Nitro Enclave"
  value       = aws_instance.plimsoll_enclave.id
}

output "private_ip" {
  description = "Private IP of the enclave instance"
  value       = aws_instance.plimsoll_enclave.private_ip
}

output "vpc_id" {
  description = "VPC ID for the enclave deployment"
  value       = aws_vpc.plimsoll.id
}

output "security_group_id" {
  description = "Security group for the enclave instance"
  value       = aws_security_group.plimsoll_enclave.id
}

output "kms_key_arn" {
  description = "KMS CMK ARN (PCR0-gated) — used for enclave key bootstrap"
  value       = local.kms_key_arn
}

output "kms_key_alias" {
  description = "KMS CMK alias"
  value       = var.create_kms_key ? aws_kms_alias.plimsoll_enclave[0].name : "N/A (external key)"
}

output "kms_endpoint_id" {
  description = "VPC endpoint ID for private KMS access (no internet needed)"
  value       = aws_vpc_endpoint.kms.id
}

output "iam_role_arn" {
  description = "IAM role ARN for the enclave instance"
  value       = aws_iam_role.plimsoll_enclave.arn
}

output "bootstrap_instructions" {
  description = "Instructions for deploying the enclave with KMS bootstrap"
  value       = <<-INSTRUCTIONS
    1. Build the enclave image:
       docker build -t plimsoll-enclave:latest -f deploy/nitro/Dockerfile.enclave .
       nitro-cli build-enclave --docker-uri plimsoll-enclave:latest --output-file plimsoll.eif

    2. Note the PCR0 hash from the build output and update:
       terraform apply -var="enclave_pcr0=<PCR0_HASH>"

    3. Copy the EIF to the instance:
       scp plimsoll.eif ec2-user@<instance_ip>:/opt/plimsoll/plimsoll.eif

    4. The enclave will automatically:
       a. Boot and request attestation from the Nitro Secure Module
       b. Call KMS Decrypt with the attestation document
       c. KMS verifies PCR0 matches the policy -> releases data key
       d. Enclave derives signing key via HKDF in isolated RAM
       e. Private key NEVER exists on the host OS
  INSTRUCTIONS
}

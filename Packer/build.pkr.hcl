# Zero-Trust AMI Build - success and failure both produce a snapshot + s3 Forensics
packer {
    required_plugins {
        amazon = {
            version = "~> 1.8.2"
            source = "github.com/hashicorp/amazon"
        }
    }
}

variable "forensics_s3_bucket" {
  type = string
}

variable "forensics_kms_key_id" {
  type    = string
  default = ""
}

variable "manifest_encryption_password" {
  type      = string
  sensitive = true
}

build {
  sources = ["source.amazon-ebs.waf_ami"]

  provisioner "shell" {
    inline = [
      "echo 'export FORENSICS_S3_BUCKET=${var.forensics_s3_bucket}' | sudo tee -a /etc/environment",
      "echo 'export FORENSICS_KMS_KEY_ID=${var.forensics_kms_key_id}' | sudo tee -a /etc/environment",
      "echo 'export MANIFEST_ENCRYPTION_PASSWORD=${var.manifest_encryption_password}' | sudo tee -a /etc/environment"
    ]
  }

  provisioner "file" {
    source      = "scripts/forensics_capture.sh"
    destination = "/tmp/forensics_capture.sh"
  }

  provisioner "shell" {
    inline = [
      "chmod +x /tmp/forensics_capture.sh"
    ]
  }

  provisioner "shell" {
    execute_command = "sudo -E bash '{{ .Path }}'"
    script          = "scripts/code_pull.tpl.sh"
  }

  provisioner "shell" {
    inline = [
      "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin"
    ]
  }

  provisioner "shell" {
  inline = [
    "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin"
  ]
}

  provisioner "shell" {
  execute_command = "sudo -E bash '{{ .Path }}'"
  inline = [
    "trivy fs / --scanners vuln,secret,misconfig --format json --output /tmp/trivy-scan.json",
    "trivy fs / --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1",
    "test -f /usr/local/bin/waf || { echo 'WAF binary missing'; exit 1; }",
    "test -f /etc/systemd/system/waf.service || { echo 'WAF unit file missing'; exit 1; }"
  ]
}

  error-cleanup-provisioner "shell" {
    inline = [
      "sudo -E /tmp/forensics_capture.sh failure"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo -E /tmp/forensics_capture.sh success"
    ]
  }
}
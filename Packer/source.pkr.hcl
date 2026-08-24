source "amazon-ebs" "waf_ami" {
  ami_name      = "waf-zero-trust-{{timestamp}}"
  instance_type = "t3.small"
  region        = "us-west-2"

  ssh_interface = "session_manager"
  ssh_username  = "ec2-user"

  source_ami_filter {
    filters = {
      name                = "al2023-ami-*-x86_64"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["137112412989"]
    most_recent = true
  }

  subnet_id                    = "subnet-007532ab1e547cfe7"
  associate_public_ip_address  = false
  iam_instance_profile         = "SandBox-ssm-profile"

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  run_volume_tags = {
    Environment = "packer-build"
  }

  tags = {
    Name = "waf-zero-trust-build"
  }
}
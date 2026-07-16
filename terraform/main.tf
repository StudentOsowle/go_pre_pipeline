terraform {
    required_providers {
        aws = {
            source = "hashicorp/aws"
            version = "~> 5.0"
        }
        random = {
            source = "hashicorp/random"
            version = "~> 3.0"
        }
    }
}

provider "aws" {
    region = var.aws_region 
}

locals {}

resource "aws_vpc" "SandBox" {
    cidr_block           = var.vpc_cidr
    enable_dns_support   = true
    enable_dns_hostnames = true
    
    tags                 = { Name = "SandBox-vpc"}
}

resource "aws_subnet" "public_bake" {
    vpc_id            = aws_vpc.SandBox.id
    cidr_block        = var.public_bake_subnet
    availability_zone = "${var.aws_region}b"
    tags              = { Name = "SandBox-bake-public"}
}

resource "aws_subnet" "private_a" {
    vpc_id            = aws_vpc.SandBox.id
    cidr_block        = var.private_a_subnet
    availability_zone = "${var.aws_region}a"
    tags              = { Name = "SandBox-private-a" }
}

resource "aws_internet_gateway" "bake_igw" {
    vpc_id = aws_vpc.SandBox.id
    tags   = { Name = "SandBox-bake-igw" }
}

resource "aws_eip" "nat" {
    domain = "vpc"
    tags   = { Name = "SandBox-nat-eip" }
}

resource "aws_nat_gateway" "bake_nat" {
    allocation_id = aws_eip.nat.id
    subnet_id     = aws_subnet.public_bake.id
    tags          = { Name = "SandBox-bake-nat"}
    depends_on    = [aws_internet_gateway.bake_igw]
}

resource "aws_route_table" "public_bake" {
    vpc_id = aws_vpc.SandBox.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.bake_igw.id
    }

    tags = { Name = "SandBox-bake-rt"}
}

resource "aws_route_table_association" "public_bake" {
    subnet_id      = aws_subnet.public_bake.id
    route_table_id = aws_route_table.public_bake.id
}

resource "aws_route_table" "private" {
    vpc_id = aws_vpc.SandBox.id
    tags   = { Name = "SandBox-private-rt"}
}

resource "aws_route" "private_nat_out" {
    route_table_id         = aws_route_table.private.id
    destination_cidr_block = "0.0.0.0/0"
    nat_gateway_id         = aws_nat_gateway.bake_nat.id
}

resource "aws_route_table_association" "private_a" {
    subnet_id      = aws_subnet.private_a.id
    route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "wazuh_server_sg" {
    name        = "SandBox-sg"
    description = "SSM-only access, outbound HTTPS for SSM + github"
    vpc_id      = aws_vpc.SandBox.id

    egress {
        description = "HTTPS out - SSM control plane + GitHub"
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = { Name = "SandBox-sg"}
}

resource "aws_iam_role" "wazuh_ssm" {
    name = "SandBox-ssm-role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
            Action    = "sts:AssumeRole"
            Effect    = "Allow"
            Principal = { Service = "ec2.amazonaws.com"}
        }]
    })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
    role       = aws_iam_role.wazuh_ssm.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "wazuh_ssm" {
    name = "SandBox-ssm-profile"
    role = aws_iam_role.wazuh_ssm.name
}

resource "aws_instance" "SandBox" {
    ami                         = var.aws_ami_image
    instance_type               = var.aws_instance_type
    subnet_id                   = aws_subnet.private_a.id
    vpc_security_group_ids      = [aws_security_group.wazuh_server_sg.id]
    iam_instance_profile        = aws_iam_instance_profile.wazuh_ssm.name
    associate_public_ip_address = false
    user_data                   = templatefile("${path.module}/code_pull.tpl.sh", {})


    tags = { Name = "SandBox"}
}
variable "aws_region" {
    description = "AWS Region"
    type        = string
}

variable "aws_ami_image" {
    description = "AMI ID for the sandbox EC2 instance"
    type        = string
    sensitive   = true
}

variable "aws_instance_type" {
    description = "ec2 instance type"
    type        = string
}

variable "vpc_cidr" {
    description = "VPC CIDR Block"
    type        = string
    sensitive   = true
}

variable "public_bake_subnet" {
    description = "CIDR for the public subnet"
    type        = string
    sensitive   = true 
}

variable "private_a_subnet" {
    description = "CIDR for the private subnet (EC2 instance)"
    type        = string
    sensitive   = true
  
}
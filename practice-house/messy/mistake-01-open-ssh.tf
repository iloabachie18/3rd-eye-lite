# PLANTED MISTAKE #1: SSH (port 22) open to the entire internet.
# Harmless: this security group is NOT attached to any server.
# 3RD EYE should detect this as HIGH risk.

# Find the messy account's default network (VPC)
data "aws_vpc" "default" {
  default = true
}

# The firewall itself
resource "aws_security_group" "ssh_open_to_world" {
  name        = "planted-ssh-open-to-world"
  description = "PLANTED MISTAKE for 3RD EYE testing - not attached to anything"
  vpc_id      = data.aws_vpc.default.id
}

# The bad rule: allow SSH from anywhere (0.0.0.0/0 = the whole internet)
resource "aws_vpc_security_group_ingress_rule" "ssh_from_anywhere" {
  security_group_id = aws_security_group.ssh_open_to_world.id
  description       = "PLANTED - SSH from anywhere"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}
# CLEAN VERSION of mistake #1.
# SSH is allowed ONLY from inside the private network (the VPC),
# never from the internet. 3RD EYE should NOT flag this.

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "ssh_private_only" {
  name        = "clean-ssh-private-only"
  description = "CLEAN - SSH allowed only from inside the VPC"
  vpc_id      = data.aws_vpc.default.id
}

# SSH only from the VPC's own private address range (e.g. 172.31.0.0/16)
resource "aws_vpc_security_group_ingress_rule" "ssh_from_vpc" {
  security_group_id = aws_security_group.ssh_private_only.id
  description       = "CLEAN - SSH from inside the VPC only"
  cidr_ipv4         = data.aws_vpc.default.cidr_block
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}
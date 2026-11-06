# PLANTED MISTAKE #4: An EBS storage volume that is NOT encrypted.
# Harmless: the volume is EMPTY, 1 GB, and attached to nothing.
# Cost: about $0.08 per month.
# 3RD EYE should detect this as MEDIUM risk.

# Find the availability zones (data centers) in us-east-1
data "aws_availability_zones" "available" {
  state = "available"
}

# The disk itself, with encryption deliberately switched off
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1     # smallest size: 1 GB
  type              = "gp3" # cheapest general-purpose type
  encrypted         = false # PLANTED: data stored unencrypted

  tags = {
    Name = "planted-unencrypted-volume"
  }
}
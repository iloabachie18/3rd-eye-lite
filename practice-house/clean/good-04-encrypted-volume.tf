# CLEAN VERSION of mistake #4.
# Account-wide default encryption ON, plus an encrypted volume.
# 3RD EYE should NOT flag this.

# Every new disk in this account is encrypted automatically
resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_ebs_volume" "encrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  encrypted         = true

  tags = {
    Name = "clean-encrypted-volume"
  }
}
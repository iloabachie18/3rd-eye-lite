# CLEAN VERSION of mistake #2.
# A private bucket, encrypted, with ALL public access blocked
# at both the bucket level AND the whole-account level.
# 3RD EYE should NOT flag this.

data "aws_caller_identity" "current" {}

# Account-wide safety net: no bucket in this account can ever be public
resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "private" {
  bucket        = "3rdeye-clean-private-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

# Bucket-level protection: all four switches ON
resource "aws_s3_bucket_public_access_block" "private" {
  bucket = aws_s3_bucket.private.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Encrypt everything stored in the bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "private" {
  bucket = aws_s3_bucket.private.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
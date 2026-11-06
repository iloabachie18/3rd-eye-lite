# PLANTED MISTAKE #2: An S3 bucket that anyone on the internet can read.
# Harmless: the bucket is EMPTY and we never upload anything to it.
# 3RD EYE should detect this as CRITICAL risk.

# Looks up the messy account's number, to make the bucket name unique
data "aws_caller_identity" "current" {}

# The bucket (S3 names must be unique across ALL of AWS worldwide)
resource "aws_s3_bucket" "public" {
  bucket        = "3rdeye-planted-public-${data.aws_caller_identity.current.account_id}"
  force_destroy = true # lets Terraform delete it cleanly later
}

# Switch OFF two of AWS's public-access protections (the planted mistake)
resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.public.id

  block_public_acls       = true  # still blocked (old-style permissions)
  ignore_public_acls      = true  # still blocked
  block_public_policy     = false # PLANTED: allows a public bucket policy
  restrict_public_buckets = false # PLANTED: allows public access
}

# The bad rule: "anyone (*) may read any file in this bucket"
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PlantedPublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public.arn}/*"
    }]
  })

  # Wait until the protections are switched off before adding the policy
  depends_on = [aws_s3_bucket_public_access_block.public]
}
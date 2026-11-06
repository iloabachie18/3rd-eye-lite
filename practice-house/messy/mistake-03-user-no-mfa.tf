# PLANTED MISTAKE #3: An IAM user who can log into the console WITHOUT MFA.
# Harmless: the user has ZERO permissions, and the random password
# is never shown to anyone.
# 3RD EYE should detect this as HIGH risk.

# The user (no policies attached = no permissions at all)
resource "aws_iam_user" "no_mfa" {
  name = "planted-user-no-mfa"
}

# Console password (the planted mistake: password but no MFA device)
resource "aws_iam_user_login_profile" "no_mfa" {
  user                    = aws_iam_user.no_mfa.name
  password_reset_required = true
}
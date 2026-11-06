# PLANTED MISTAKE #5: A weak account password policy.
# Harmless: only affects the messy account, whose only user
# already has a strong 20-character random password.
# 3RD EYE should detect this as MEDIUM risk.

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6     # PLANTED: AWS's lowest allowed (14+ is recommended)
  require_lowercase_characters   = false # PLANTED
  require_uppercase_characters   = false # PLANTED
  require_numbers                = false # PLANTED
  require_symbols                = false # PLANTED
  allow_users_to_change_password = true
  max_password_age               = 0     # PLANTED: passwords never expire
  # password_reuse_prevention left out = old passwords can be reused (PLANTED)
}
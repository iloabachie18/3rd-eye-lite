# CLEAN VERSION of mistake #5.
# A strong password policy following CIS benchmark guidance.
# 3RD EYE should NOT flag this.

resource "aws_iam_account_password_policy" "strong" {
  minimum_password_length        = 14   # CIS recommends 14 or more
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24   # can't reuse the last 24 passwords
  max_password_age               = 90   # must change every 90 days
}
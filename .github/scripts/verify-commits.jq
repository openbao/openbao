# Expects the list of commits on a pull requests as input.
# See: https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28#list-commits-on-a-pull-request
[
  # Iterate over all commits
  .[] |
  # select maintainer commits
  select(
    .author.login == "JanMa" or
    .author.login == "cipherboy" or
    .author.login == "DanGhita" or
    .author.login == "naphelps"
  ) |
  # select any unsigned commits
  select(.commit.verification.verified == false)
] |
# check if there are unsigned commits
if (. | length) != 0 then
  # return error
  ("Pr contains unsigned maintainer commits!\n" | halt_error(1))
else
  # return success
  "All maintainer commits are signed"
end

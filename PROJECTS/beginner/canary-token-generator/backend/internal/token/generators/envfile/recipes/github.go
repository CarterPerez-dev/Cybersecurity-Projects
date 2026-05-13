// ©AngelaMos | 2026
// github.go

package recipes

const (
	githubTokenPrefix    = "ghp_"
	githubTokenBodyLen   = 36
	githubChecksumLen    = 6
	githubDeployKeyBytes = 32

	githubOwnerName = "acme-corp"
	githubRepoName  = "internal-platform"
)

type GitHub struct{}

func (GitHub) Name() string { return keyGitHub }

func (GitHub) Generate() []EnvLine {
	body := RandomAlnumMixed(githubTokenBodyLen)
	checksum := RandomAlnumMixed(githubChecksumLen)
	return []EnvLine{
		{Comment: "GitHub deploy + automation tokens"},
		{
			Key:   "GITHUB_TOKEN",
			Value: githubTokenPrefix + body + checksum,
		},
		{
			Key:   "GITHUB_DEPLOY_KEY",
			Value: RandomBase64(githubDeployKeyBytes),
		},
		{
			Key:   "GITHUB_OWNER",
			Value: githubOwnerName,
		},
		{
			Key:   "GITHUB_REPO",
			Value: githubRepoName,
		},
	}
}

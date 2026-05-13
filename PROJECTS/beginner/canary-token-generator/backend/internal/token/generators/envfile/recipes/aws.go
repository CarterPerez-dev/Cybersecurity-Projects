// ©AngelaMos | 2026
// aws.go

package recipes

const (
	awsAccessKeyPrefix  = "AKIA"
	awsAccessKeyBodyLen = 16
	awsSecretBytes      = 30

	awsBucketName = "prod-data-backups"
)

var awsRegions = []string{
	"us-east-1",
	"us-east-2",
	"us-west-2",
	"eu-west-1",
	"eu-central-1",
	"ap-southeast-1",
	"ap-northeast-1",
}

type AWS struct{}

func (AWS) Name() string { return keyAWS }

func (AWS) Generate() []EnvLine {
	return []EnvLine{
		{Comment: "AWS S3 production bucket (" + awsBucketName + ")"},
		{
			Key:   "AWS_ACCESS_KEY_ID",
			Value: awsAccessKeyPrefix + RandomAlnumUpper(awsAccessKeyBodyLen),
		},
		{
			Key:   "AWS_SECRET_ACCESS_KEY",
			Value: RandomBase64(awsSecretBytes),
		},
		{
			Key:   "AWS_REGION",
			Value: RandomChoice(awsRegions),
		},
		{
			Key:   "AWS_S3_BUCKET",
			Value: awsBucketName,
		},
	}
}

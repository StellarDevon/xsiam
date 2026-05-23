package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	WebPort      string
	InternalPort string
	Mode         string
	WebhookURL   string // alert callback from datalake → internal port
	ArangoDB     ArangoDBConfig
	Auth         AuthConfig
	Stub         StubConfig
	DataLake     DataLakeConfig
	Notify       NotifyConfig
}

type ArangoDBConfig struct {
	Endpoints []string
	Username  string
	Password  string
	Database  string
}

type AuthConfig struct {
	JWTSecret    string
	TokenExpireHr int
}

type StubConfig struct {
	Execution bool
	ETL       bool
	DataLake  bool
	AIEngine  bool
}

type DataLakeConfig struct {
	QueryURL string
	HECURL   string
	HECToken string
	Enabled  bool
}

type NotifyConfig struct {
	Email    EmailConfig
	DingTalk DingTalkConfig
	Slack    SlackConfig
}

type EmailConfig struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type DingTalkConfig struct {
	Enabled    bool
	WebhookURL string
}

type SlackConfig struct {
	Enabled    bool
	WebhookURL string
}

func Load() *Config {
	viper.SetConfigFile("config.yaml")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()

	webPort := viper.GetString("SERVER_PORT")
	if webPort == "" {
		webPort = "18080"
	}
	internalPort := viper.GetString("INTERNAL_PORT")
	if internalPort == "" {
		internalPort = "18090"
	}

	return &Config{
		WebPort:      webPort,
		InternalPort: internalPort,
		Mode:         viper.GetString("SERVER_MODE"),
		ArangoDB: ArangoDBConfig{
			Endpoints: viper.GetStringSlice("ARANGO_ENDPOINTS"),
			Username:  viper.GetString("ARANGO_USERNAME"),
			Password:  viper.GetString("ARANGO_PASSWORD"),
			Database:  viper.GetString("ARANGO_DATABASE"),
		},
		Auth: AuthConfig{
			JWTSecret:    viper.GetString("JWT_SECRET"),
			TokenExpireHr: viper.GetInt("JWT_EXPIRE_HR"),
		},
		Stub: StubConfig{
			Execution: viper.GetBool("STUB_EXECUTION"),
			ETL:       viper.GetBool("STUB_ETL"),
			DataLake:  viper.GetBool("STUB_DATALAKE"),
			AIEngine:  viper.GetBool("STUB_AI_ENGINE"),
		},
		DataLake: DataLakeConfig{
			QueryURL: viper.GetString("DATALAKE_QUERY_URL"),
			HECURL:   viper.GetString("DATALAKE_HEC_URL"),
			HECToken: viper.GetString("DATALAKE_HEC_TOKEN"),
			Enabled:  viper.GetBool("DATALAKE_ENABLED"),
		},
		WebhookURL: viper.GetString("WEBHOOK_URL"),
		Notify: NotifyConfig{
			Email: EmailConfig{
				Enabled:  viper.GetBool("NOTIFY_EMAIL_ENABLED"),
				Host:     viper.GetString("NOTIFY_EMAIL_HOST"),
				Port:     viper.GetInt("NOTIFY_EMAIL_PORT"),
				Username: viper.GetString("NOTIFY_EMAIL_USERNAME"),
				Password: viper.GetString("NOTIFY_EMAIL_PASSWORD"),
				From:     viper.GetString("NOTIFY_EMAIL_FROM"),
			},
			DingTalk: DingTalkConfig{
				Enabled:    viper.GetBool("NOTIFY_DINGTALK_ENABLED"),
				WebhookURL: viper.GetString("NOTIFY_DINGTALK_WEBHOOK_URL"),
			},
			Slack: SlackConfig{
				Enabled:    viper.GetBool("NOTIFY_SLACK_ENABLED"),
				WebhookURL: viper.GetString("NOTIFY_SLACK_WEBHOOK_URL"),
			},
		},
	}
}

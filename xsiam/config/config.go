package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	WebPort       string
	InternalPort  string
	Mode          string
	WebhookURL    string // alert callback from datalake → internal port
	ArangoDB      ArangoDBConfig
	Auth          AuthConfig
	Stub          StubConfig
	DataLake      DataLakeConfig
	Notify        NotifyConfig
	Webhook       WebhookConfig `mapstructure:"webhook"`
	RedisAddr     string // host:port, e.g. "localhost:6379"
	RedisPassword string
	CopilotAPIKey string `mapstructure:"copilot_api_key"`
	GeoIP         GeoIPConfig
}

// GeoIPConfig points to MaxMind GeoLite2 offline database files.
// Both paths are optional: if empty the corresponding enrichment is disabled.
type GeoIPConfig struct {
	CityDBPath string // path to GeoLite2-City.mmdb
	ASNDBPath  string // path to GeoLite2-ASN.mmdb (optional)
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
	Webhook  WebhookNotifyConfig
}

// WebhookNotifyConfig is for outbound notification webhooks (distinct from the
// inbound alert-ingest WebhookConfig at the top-level Config).
type WebhookNotifyConfig struct {
	Enabled bool
	URLs    []string
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

type WebhookConfig struct {
	Endpoints []string `mapstructure:"endpoints"`
	Secret    string   `mapstructure:"secret"`
}

// configPath resolves the config file location.
// Search order:
//  1. ./config.yaml           (current working directory — dev mode, run from xsiam/)
//  2. <exe-dir>/config.yaml   (production — exe in output/bin/, config in output/)
//  3. <exe-dir>/../config.yaml (exe in output/bin/, config one level up in output/)
func configPath() string {
	candidates := []string{"config.yaml"}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "config.yaml"),
			filepath.Join(exeDir, "..", "config.yaml"),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "config.yaml" // fallback; viper will warn but not fatal
}

func Load() *Config {
	viper.SetConfigFile(configPath())
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
	_ = viper.BindEnv("copilot_api_key", "ANTHROPIC_API_KEY")

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
		Webhook: WebhookConfig{
			Endpoints: viper.GetStringSlice("webhook.endpoints"),
			Secret:    viper.GetString("webhook.secret"),
		},
		RedisAddr:     func() string { a := viper.GetString("REDIS_ADDR"); if a == "" { return "localhost:6379" }; return a }(),
		RedisPassword: viper.GetString("REDIS_PASSWORD"),
		CopilotAPIKey: viper.GetString("copilot_api_key"),
		GeoIP: GeoIPConfig{
			CityDBPath: viper.GetString("GEOIP_CITY_DB"),
			ASNDBPath:  viper.GetString("GEOIP_ASN_DB"),
		},
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
			Webhook: WebhookNotifyConfig{
				Enabled: viper.GetBool("NOTIFY_WEBHOOK_ENABLED"),
				URLs:    viper.GetStringSlice("NOTIFY_WEBHOOK_URLS"),
			},
		},
	}
}

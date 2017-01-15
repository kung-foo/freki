package freki

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"

	yaml "gopkg.in/yaml.v2"

	"golang.org/x/net/bpf"
)

type RuleType int

const (
	Rewrite RuleType = iota
	Proxy
	LogTCP
	LogHTTP
	Drop
	PassThrough
)

type Config struct {
	Rules []*Rule `yaml:"rules"`
}

type Rule struct {
	Match  string `yaml:"match"`
	Type   string `yaml:"type"`
	Target string `yaml:"target,omitempty"`

	isInit    bool
	ruleType  RuleType
	index     int
	matcher   *bpf.VM
	targetURL *url.URL

	host        string
	port        int
	rewriteAddr net.IP
}

func ReadRulesFromFile(file *os.File) ([]*Rule, error) {
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return ParseRuleSpec(data)
}

func ParseRuleSpec(spec []byte) ([]*Rule, error) {
	config := &Config{}
	err := yaml.Unmarshal(spec, config)

	for idx, rule := range config.Rules {
		err = initRule(idx, rule)
		if err != nil {
			return nil, err
		}
	}

	return config.Rules, err
}

func initRule(idx int, rule *Rule) error {
	if len(rule.Match) > 0 {
		// TODO: fix device name
		// TODO: better yet, find a different bpf compiler
		h, err := pcap.OpenLive("eth0", 1, false, time.Second)
		if err != nil {
			return err
		}
		defer h.Close()

		instuctions, err := h.CompileBPFFilter(rule.Match)
		if err != nil {
			return errors.Wrap(err, rule.Match)
		}

		rule.matcher = pcapBPFToXNetBPF(instuctions)
	}

	if rule.Target != "" {
		var err error
		rule.targetURL, err = url.Parse(rule.Target)

		if err != nil {
			return err
		}

		var sport string
		rule.host, sport, err = net.SplitHostPort(rule.targetURL.Host)

		if err != nil {
			return err
		}

		rule.port, err = strconv.Atoi(sport)

		if err != nil {
			return err
		}

		/*
			if rule.targetURL.Scheme == "tcp" {
				// TODO: logic might be different. rewrite vs proxy, etc.
				var addrs []net.IP
				addrs, err = net.LookupIP(rule.host)

				if err != nil {
					return err
				}

				if len(addrs) == 0 {
					return fmt.Errorf("unabled to resolve: %s", rule.host)
				}

				rule.rewriteAddr = addrs[0]
			}
		*/
	}

	switch rule.Type {
	case "rewrite":
		rule.ruleType = Rewrite
	case "proxy":
		rule.ruleType = Proxy
	case "log_tcp":
		rule.ruleType = LogTCP
	case "log_http":
		rule.ruleType = LogHTTP
	case "drop":
		rule.ruleType = Drop
	case "passthrough":
		rule.ruleType = PassThrough
	default:
		return fmt.Errorf("unknown rule type: %s", rule.Type)
	}

	rule.index = idx
	rule.isInit = true

	return nil
}

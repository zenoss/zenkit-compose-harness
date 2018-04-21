package test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"net"

	"github.com/cenkalti/backoff"
	"github.com/docker/libcompose/config"
	"github.com/docker/libcompose/docker"
	lclient "github.com/docker/libcompose/docker/client"
	"github.com/docker/libcompose/docker/container"
	"github.com/docker/libcompose/docker/ctx"
	"github.com/docker/libcompose/labels"
	"github.com/docker/libcompose/project"
	"github.com/docker/libcompose/project/options"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var (
	// nameRegexp is a copy of a pattern from libcompose, because the sanitized
	// name isn't gettable from the project for some reason, so we have to run
	// it ourselves
	nameRegexp = regexp.MustCompile("[^a-z0-9]+")
	// ErrNoContainerFound is raised when we don't find any containers using the filters specified
	ErrNoContainerFound = errors.New("no containers found")
	// ErrNoConfigFound is returned when no config for a specified service
	ErrNoConfigFound = errors.New("no config found")
	// ErrNotInEnv is returned when no variable exists in an environment for the given key
	ErrNotInEnv = errors.New("variable is not in environment")
)

type Harness interface {
	Start() error
	Stop() error
	Wait(healthcheck func() error, timeout time.Duration) error
	Resolve(service string, port uint64) (string, error)
	GetFromEnv(service, key string) (string, error)
}

type dockerComposeHarness struct {
	name        string
	project     project.APIProject
	dns         *dns.Server
	oldResolver *net.Resolver
	ctx         context.Context
}

func normalizeName(name string) string {
	return nameRegexp.ReplaceAllString(strings.ToLower(name), "")
}

func (h *dockerComposeHarness) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	var m dns.Msg
	m.SetReply(r)
	m.Compress = false
	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			switch q.Qtype {
			case dns.TypeA:
				name := strings.TrimRight(q.Name, ".")
				ip, err := h.ResolveIP(name)

				if err == nil && ip != "" {
					rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		}
	}
	w.WriteMsg(&m)
}

func StartDNSServer(handler func(dns.ResponseWriter, *dns.Msg)) (*dns.Server, string) {
	dns.HandleFunc(".", handler)
	server := &dns.Server{Addr: ":0", Net: "udp"}
	go server.ListenAndServe()
	time.Sleep(time.Second)
	addr := server.PacketConn.LocalAddr().String()
	return server, addr
}

func NewDockerComposeHarness(name string, dockerComposeFiles ...string) (Harness, error) {
	c := context.Background()
	name = normalizeName(name)
	proj, err := docker.NewProject(&ctx.Context{
		Context: project.Context{
			ComposeFiles: dockerComposeFiles,
			ProjectName:  name,
		},
	}, &config.ParseOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create libcompose project")
	}

	return &dockerComposeHarness{
		ctx:     c,
		name:    name,
		project: proj,
	}, nil
}

func (h *dockerComposeHarness) Start() error {
	server, addr := StartDNSServer(h.handleDNS)
	h.dns = server

	h.oldResolver = net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr, _ := net.ResolveUDPAddr("udp4", addr)
			return net.DialUDP(network, nil, addr)
		},
	}

	if err := h.project.Up(h.ctx, options.Up{}); err != nil {
		return errors.Wrap(err, "unable to bring up the libcompose project")
	}

	return nil
}

func (h *dockerComposeHarness) Stop() error {
	h.dns.Shutdown()
	net.DefaultResolver = h.oldResolver
	if err := h.project.Down(h.ctx, options.Down{}); err != nil {
		return errors.Wrap(err, "unable to shut down the libcompose project")

	}
	return nil
}

func (h *dockerComposeHarness) Resolve(service string, port uint64) (string, error) {
	ip, err := h.ResolveIP(service)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", ip, port), nil
}

func (h *dockerComposeHarness) ResolveIP(service string) (string, error) {
	client, err := lclient.Create(lclient.Options{})
	if err != nil {
		return "", errors.Wrap(err, "unable to create Docker client")
	}
	filter := labels.And(labels.PROJECT.Eq(h.name), labels.SERVICE.Eq(service))
	containers, err := container.ListByFilter(h.ctx, client, filter)
	if err != nil {
		return "", errors.Wrap(err, "unable to filter service containers")
	}
	if len(containers) == 0 {
		return "", errors.WithStack(ErrNoContainerFound)
	}
	net := containers[0].NetworkSettings.Networks["bridge"]
	return net.IPAddress, nil
}

func (h *dockerComposeHarness) Wait(healthcheck func() error, timeout time.Duration) error {
	boff := backoff.NewExponentialBackOff()
	boff.MaxElapsedTime = timeout
	boff.InitialInterval = 500 * time.Millisecond
	boff.Multiplier = 1.0
	if err := backoff.Retry(healthcheck, boff); err != nil {
		return errors.Wrap(err, "health check didn't pass within the timeout")
	}
	return nil
}

func (h *dockerComposeHarness) GetFromEnv(service, key string) (string, error) {
	cfg, found := h.project.GetServiceConfig(service)
	if !found {
		return "", ErrNoConfigFound
	}
	for _, envVar := range cfg.Environment {
		split := strings.Split(envVar, "=")
		if len(split) == 2 {
			if split[0] == key {
				return split[1], nil
			}
		}
	}
	return "", ErrNotInEnv
}

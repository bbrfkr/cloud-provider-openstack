/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"crypto/tls"
	"net/http"
	"os"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v3/snapshots"
	gcfg "gopkg.in/gcfg.v1"
	netutil "k8s.io/apimachinery/pkg/util/net"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog"

	"github.com/gophercloud/gophercloud/openstack/identity/v3/extensions/trusts"
	tokens3 "github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
)

type IOpenStack interface {
	CreateVolume(name string, size int, vtype, availability string, tags *map[string]string) (string, string, int, error)
	DeleteVolume(volumeID string) error
	AttachVolume(instanceID, volumeID string) (string, error)
	ListVolumes() ([]Volume, error)
	WaitDiskAttached(instanceID string, volumeID string) error
	DetachVolume(instanceID, volumeID string) error
	WaitDiskDetached(instanceID string, volumeID string) error
	GetAttachmentDiskPath(instanceID, volumeID string) (string, error)
	GetVolumesByName(name string) ([]Volume, error)
	CreateSnapshot(name, volID, description string, tags *map[string]string) (*snapshots.Snapshot, error)
	ListSnapshots(limit, offset int, filters map[string]string) ([]snapshots.Snapshot, error)
	DeleteSnapshot(snapID string) error
}

type OpenStack struct {
	compute      *gophercloud.ServiceClient
	blockstorage *gophercloud.ServiceClient
}

type Config struct {
	Global struct {
		AuthUrl    string `gcfg:"auth-url"`
		Username   string
		UserId     string `gcfg:"user-id"`
		Password   string
		TenantId   string `gcfg:"tenant-id"`
		TenantName string `gcfg:"tenant-name"`
		TrustID    string `gcfg:"trust-id"`
		DomainId   string `gcfg:"domain-id"`
		DomainName string `gcfg:"domain-name"`
		Region     string
		CAFile     string `gcfg:"ca-file"`
	}
}

func (cfg Config) toAuthOptions() gophercloud.AuthOptions {
	return gophercloud.AuthOptions{
		IdentityEndpoint: cfg.Global.AuthUrl,
		Username:         cfg.Global.Username,
		UserID:           cfg.Global.UserId,
		Password:         cfg.Global.Password,
		TenantID:         cfg.Global.TenantId,
		TenantName:       cfg.Global.TenantName,
		DomainID:         cfg.Global.DomainId,
		DomainName:       cfg.Global.DomainName,

		// Persistent service, so we need to be able to renew tokens.
		AllowReauth: true,
	}
}

func (cfg Config) toAuth3Options() tokens3.AuthOptions {
	return tokens3.AuthOptions{
		IdentityEndpoint: cfg.Global.AuthUrl,
		Username:         cfg.Global.Username,
		UserID:           cfg.Global.UserId,
		Password:         cfg.Global.Password,
		DomainID:         cfg.Global.DomainId,
		DomainName:       cfg.Global.DomainName,
		AllowReauth:      true,
	}
}

// GetConfigFromFile retrieves config options from file
func GetConfigFromFile(configFilePath string) (Config, trusts.AuthOptsExt, string, gophercloud.EndpointOpts, error) {
	var epOpts gophercloud.EndpointOpts
	var cfg Config
	var authOptsExt trusts.AuthOptsExt
	var authUrl string

	config, err := os.Open(configFilePath)
	if err != nil {
		klog.V(3).Infof("Failed to open OpenStack configuration file: %v", err)
		return cfg, authOptsExt, authUrl, epOpts, err
	}
	defer config.Close()

	err = gcfg.FatalOnly(gcfg.ReadInto(&cfg, config))
	if err != nil {
		klog.V(3).Infof("Failed to read OpenStack configuration file: %v", err)
		return cfg, authOptsExt, authUrl, epOpts, err
	}

	epOpts = gophercloud.EndpointOpts{
		Region: cfg.Global.Region,
	}

	authUrl = cfg.Global.AuthUrl

 	if cfg.Global.TrustID != "" {
		opts := cfg.toAuth3Options()
		authOptsExt = trusts.AuthOptsExt{
			TrustID:            cfg.Global.TrustID,
			AuthOptionsBuilder: &opts,
		}
	}

	return cfg, authOptsExt, authUrl, epOpts, nil
}

// GetConfigFromEnv retrieves config options from env
func GetConfigFromEnv() (gophercloud.AuthOptions, gophercloud.EndpointOpts, error) {
	// Get config from env
	authOpts, err := openstack.AuthOptionsFromEnv()
	var epOpts gophercloud.EndpointOpts
	if err != nil {
		klog.V(3).Infof("Failed to read OpenStack configuration from env: %v", err)
		return authOpts, epOpts, err
	}

	epOpts = gophercloud.EndpointOpts{
		Region: os.Getenv("OS_REGION_NAME"),
	}

	return authOpts, epOpts, nil
}

var OsInstance IOpenStack = nil
var configFile = "/etc/cloud.conf"

func InitOpenStackProvider(cfg string) {
	configFile = cfg
	klog.V(2).Infof("InitOpenStackProvider configFile: %s", configFile)
}

// GetOpenStackProvider returns Openstack Instance
func GetOpenStackProvider() (IOpenStack, error) {
	var authOpts gophercloud.AuthOptions
	var authURL string
	var caFile string

	if OsInstance != nil {
		return OsInstance, nil
	}
	// Get config from file
	cfg, authOptsExt, authURL, epOpts, err := GetConfigFromFile(configFile)
	if err == nil {
		authOpts = cfg.toAuthOptions()
		caFile = cfg.Global.CAFile
	} else {
		// Get config from env
		authOpts, epOpts, err = GetConfigFromEnv()
		if err != nil {
			return nil, err
		}
	}

	provider, err := openstack.NewClient(authURL)
	if err != nil {
		return nil, err
	}

	if caFile != "" {
		roots, err := certutil.NewPool(caFile)
		if err != nil {
			return nil, err
		}
		config := &tls.Config{}
		config.RootCAs = roots
		provider.HTTPClient.Transport = netutil.SetOldTransportDefaults(&http.Transport{TLSClientConfig: config})
	}

	if &authOptsExt != nil {
		err = openstack.AuthenticateV3(provider, authOptsExt, gophercloud.EndpointOpts{})
	} else {
		err = openstack.Authenticate(provider, authOpts)
	}
	if err != nil {
		return nil, err
	}

	// Init Nova ServiceClient
	computeclient, err := openstack.NewComputeV2(provider, epOpts)
	if err != nil {
		return nil, err
	}

	// Init Cinder ServiceClient
	blockstorageclient, err := openstack.NewBlockStorageV3(provider, epOpts)
	if err != nil {
		return nil, err
	}

	// Init OpenStack
	OsInstance = &OpenStack{
		compute:      computeclient,
		blockstorage: blockstorageclient,
	}

	return OsInstance, nil
}